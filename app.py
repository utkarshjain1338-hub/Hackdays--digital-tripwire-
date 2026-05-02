from flask import Flask, request, render_template
import database

app = Flask(__name__)

# Ensure DB is initialized
database.init_db()

@app.route('/', methods=['GET', 'POST'])
def index():
    db = database.get_db()
    cursor = db.cursor()
    
    search_query = request.form.get('search', '')
    
    if search_query:
        # VULNERABLE CODE: Direct string interpolation (SQL Injection)
        # This is intentional for the honeypot simulation
        query = f"SELECT * FROM inventory WHERE name LIKE '%{search_query}%'"
        try:
            cursor.execute(query)
            results = cursor.fetchall()
        except Exception as e:
            results = []
            print(f"Error executing query: {e}")
    else:
        cursor.execute("SELECT * FROM inventory")
        results = cursor.fetchall()
        
    db.close()
    
    return render_template('index.html', items=results, search_query=search_query)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
