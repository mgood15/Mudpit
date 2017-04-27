# Mudpit - Snort Visualizer #

## About the Tool ##
- Mudpit is a Dashboard for visuals developed from Snort's "Fast Alerts".
- It allows for users to see their network and statistics from a different perspective that is not easily available from the existing Squert interface.
- It auto-refreshes and reloads the Flask application to provide a live-feed of data.


## Special Pre-Configuration ##
- Python3 and pip3 should be installed on the system.
- Configure Snort to write to the "/var/log/snort/alerts" file using the "Fast Alerts".
- Mudpit pulls from that file and parses the log to create a dashboard, so the user running the tool must have permission to at least read the "alerts" file.
- Plotly is a graphing tool. To use Plotly for any adjustment of this tool, you have to make an account on the website to get an API token. Plotly can be found at [this address.](https://plot.ly/)
- Instructions for configuring the API token on the system is found [here.](https://plot.ly/python/getting-started/) (Note that this project is written in Python3 so their instructions need to be done for Python3 and Pip3).

## Onboarding and Packages to Install ##
Mudpit has a few Python package dependencies needed to run:

```
pip3 install geocoder
pip3 install plotly
pip3 install numpy
pip3 install networkx
pip3 install matplotlib
pip3 install flask
pip3 install flask_bootstrap
```

## How to Use ##
- Download the repository.
- Make sure Snort is logging "Fast Alerts" to the "/var/log/snort/alerts" file (tool will not run if file does not exist).

To start Mudpit:  ``` python3 mudpit.py ```
Then open up a browser window and go to: ``` localhost:5000 ``` and the tool should load the Mudpit Dashboard. This dashboard automatically reloads every two minutes and updates.


## Existing Tools and Resources ##

Mudpit is a visualizing tool for Snort, therefore having a valid Snort set-up is required. Snort documentation can be found [here.](https://www.snort.org/documents#OfficialDocumentation)

Flask was used for the application. Flask documentation can be found [here.](http://flask.pocoo.org/docs/0.12/)

I also use a Python library called Geocoder to allow country lookup according to IP address. Documentation can be found [here.](http://geocoder.readthedocs.io/index.html)

Plotly (a powerful visual graphing tool with Python support) is also used for visuals. Information about Plotly can be found [here.](https://plot.ly/)
