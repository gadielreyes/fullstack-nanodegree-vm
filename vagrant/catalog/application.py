from flask import Flask, render_template, request, redirect, jsonify, url_for, flash

from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, CatalogItem, User

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"


# Connect to Database and create database session
engine = create_engine('sqlite:///catalogapp.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

categories = session.query(Category).order_by(asc(Category.name))

# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state, categories=categories)

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]


    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout, let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output

@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

def isUserCreator(user_id):
    creator = getUserInfo(user_id)
    if creator.id == login_session['user_id']:
        return True


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# Show latest items
@app.route('/')
@app.route('/catalog/')
def showLatestItems():
    latestItems = session.query(CatalogItem).order_by(desc(CatalogItem.id)).all()
    if 'username' not in login_session:
        return render_template('publiclatestitems.html', categories=categories, latest_items=latestItems)
    else:
        return render_template('latestitems.html', categories=categories, latest_items=latestItems)

# Show category items
@app.route('/catalog/<string:category_name>/items')
def showCategoryItems(category_name):
    category = session.query(Category).filter_by(name=category_name).first()
    categoryItems = session.query(CatalogItem).filter_by(category_id=category.id).order_by(CatalogItem.title)
    creator = getUserInfo(category.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publiccategoryitems.html', categories=categories, category_items=categoryItems, category_name=category_name)
    else:
        return render_template('categoryitems.html', categories=categories, category_items=categoryItems, category_name=category_name)

# Show a catalog item
@app.route('/catalog/<string:category_name>/<string:item_title>')
def showCatalogItem(category_name, item_title):
    catalogItem = session.query(CatalogItem).filter_by(title=item_title).first()
    creator = getUserInfo(catalogItem.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publiccatalogitem.html', item=catalogItem)
    else:
        return render_template('catalogitem.html', item=catalogItem)

# Create a new category
@app.route('/catalog/category/new', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        name = request.form['name']
        category = session.query(Category).filter_by(name=name).all()
        if category:
            flash('Name of the category already exists. Try another name please.')
            return render_template('newcategory.html', categories = categories)
        else:
            newCategory = Category(name=name, user_id=login_session['user_id'])
            session.add(newCategory)
            session.commit()
            flash('New Category %s Successfully Created' % newCategory.name)
            return redirect(url_for('showLatestItems'))
    else:
        return render_template('newcategory.html', categories = categories)

# Edite a category
@app.route('/catalog/category/<string:category_name>/edit', methods=['GET', 'POST'])
def editCategory(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    editedCategory = session.query(Category).filter_by(name=category_name).first()
    if not isUserCreator(editedCategory.user_id):
        flash('You are not the creator of this category');
        return redirect(url_for('showLatestItems'))
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
            flash('Category Successfully Edited %s' % editedCategory.name)
        return redirect(url_for('showLatestItems'))
    else:
        return render_template('editcategory.html', categories=categories, category=editedCategory)

# Delete a restaurant
@app.route('/catalog/category/<string:category_name>/delete', methods=['GET', 'POST'])
def deleteCategory(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    categoryToDelete = session.query(Category).filter_by(name=category_name).first()
    if not isUserCreator(categoryToDelete.user_id):
        flash('You are not the creator of this category');
        return redirect(url_for('showLatestItems'))
    if request.method == 'POST':
        session.delete(categoryToDelete)
        flash('%s Successfully Deleted' % categoryToDelete.name)
        session.commit()
        return redirect(url_for('showLatestItems'))
    else:
        return render_template('deletecategory.html', categories=categories, restaurant=categoryToDelete)

# Create a new catalog item
@app.route('/catalog/item/new', methods=['GET', 'POST'])
def newCatalogItem():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        category = session.query(Category).filter_by(id=request.form['category']).one()
        title = request.form['title']
        catalogItem = session.query(CatalogItem).filter_by(title=title).all()
        if catalogItem:
            flash('Title of the item already exists. Try another title please.')
            return render_template('newcatalogitem.html', categories=categories)
        else:
            newItem = CatalogItem(title=request.form['title'], description=request.form['description'],
                                    category_id=category.id, user_id=category.user_id)
            session.add(newItem)
            session.commit()
            flash('New Catalog %s Item Successfully Created' % (newItem.title))
            return redirect(url_for('showCatalogItem', category_name=category.name, item_title=newItem.title))
    else:
        return render_template('newcatalogitem.html', categories=categories)

# Edit a catalog item
@app.route('/catalog/item/<string:item_title>/edit', methods=['GET', 'POST'])
def editCatalogItem(item_title):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(CatalogItem).filter_by(title=item_title).first()
    category = session.query(Category).filter_by(id=editedItem.category_id).one()
    if not isUserCreator(editedItem.user_id):
        flash('You are not the creator of this item');
        return redirect(url_for('showLatestItems'))
    if request.method == 'POST':
        if request.form['title']:
            editedItem.title = request.form['title']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['category']:
            editedItem.category_id = request.form['category']
        session.add(editedItem)
        session.commit()
        flash('Catalog Item Successfully Edited')
        return redirect(url_for('showCategoryItems', category_name=category.name))
    else:
        return render_template('editcatalogitem.html', categories=categories, item=editedItem)

# Delete a catalog item
@app.route('/catalog/item/<string:item_title>/delete', methods=['GET', 'POST'])
def deleteCatalogItem(item_title):
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = session.query(CatalogItem).filter_by(title=item_title).first()
    category = session.query(Category).filter_by(id=itemToDelete.category_id).first()
    if not isUserCreator(itemToDelete.user_id):
        flash('You are not the creator of this item');
        return redirect(url_for('showLatestItems'))
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Catalog Item Successfully Deleted')
        return redirect(url_for('showCategoryItems', category_name=category.name))
    else:
        return render_template('deletecatalogitem.html', item=itemToDelete)

# show catalog in a JSON format
@app.route('/catalog.json')
def catalogJSON():
    result = []
    categories = session.query(Category).all()
    for category in categories:
        items = session.query(CatalogItem).filter_by(category_id=category.id).all()
        currentCategory = {}
        currentCategory['id'] = category.id
        currentCategory['name'] = category.name
        if items:
            currentCategory['items'] = [i.serialize for i in items]
        result.append(currentCategory)
    return jsonify(Category = result)

# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showLatestItems'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showLatestItems'))

if __name__ == '__main__':
    app.secret_key = 'mega_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
