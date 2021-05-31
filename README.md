This is a small utility parses all the FedRAMP controls and displays
the compliance as code content rules that apply to those controls.

Instructions
------------

I'm running on a Fedora system; So here's what I did:

```
# Clone the repo
git clone https://github.com/JAORMX/fedrampparse.git
cd fedrampparse

# Install pip and virtualenv
sudo dnf install -y python3-virtualenv python3-pip

# Create a virtual environment
virtualenv .venv

# Use the virtual environment
source .venv/bin/activate

# Install the dependencies
pip install -r requirements.txt

Note that the `jira` dependency is optional, but useful.

# See the different options
./fedrampread.py -h

# Run the tool
./fedrampread.py
```

Note that the tool displays the result to standard output. However, you can
specify which file to write the output to.

It is also possible to specify a different baseline than moderate (e.g. high or
low).
