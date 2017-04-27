from flask import Flask, render_template, json
from flask_bootstrap import Bootstrap
import parser
import graphs

def init():
    """Initializing function of the Flask app for the Snort dashboard.
    """
    app = Flask(__name__)
    Bootstrap(app)
    app.config['TEMPLATES_AUTO_RELOAD'] = True

    @app.route('/')
    def index():
        """Starts the Flask app and calls parse.py's main parsing
        function and then calls graphs.py's main visualization
        function.  After these functions run, the dashboard home
        template is rendered and shown to the user.
        """
        parser.parse_everything()
        graphs.visualize()

        return render_template('index.html')

    @app.after_request
    def reload(response):
        with open ('_reload.py', "a") as f:
            f.write("1")
        return response
    return app

if __name__ == "__main__":
    init().run(debug=True, extra_files=['_reload.py'])
