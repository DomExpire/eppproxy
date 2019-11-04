import os

# address to bind to
INTERFACE = os.environ.get('INTERFACE', '0.0.0.0')

# port on which to listen for plain connections
ENABLED = False
LISTEN_PORT = 6999

# serve SSL connections, you need to configure the certficates
SSL_ENABLED = True
SSL_LISTEN_PORT = 700
SSL_KEY = os.environ.get('SSL_KEY', './certs/serverkey.pem')
SSL_CRT = os.environ.get('SSL_CRT', './certs/servercert.pem')

# master EPP server to which to connect to. If the server requires you to
# connect using client SSL certificate configure it here, otherwise leave
# as None. CONNECTIONS is number of permanent connections proxy will try
# to maintain at any given time
EPP_HOST = os.environ.get('EPP_HOST', 'epp.sandbox.nic.fr')
EPP_PORT = int(os.environ.get('EPP_PORT', 700))
CLIENT_SSL_KEY = os.environ.get('CLIENT_SSL_KEY', './certs/clientkey.pem')
CLIENT_SSL_CRT = os.environ.get('CLIENT_SSL_CRT', './certs/clientcert.pem')

USERNAME = os.environ.get('USERNAME')
PASSWORD = os.environ.get('PASSWORD')

CONNECTIONS = int(os.environ.get('CONNECTIONS', 3))

# error mail settings, proxy sends mail on failure
MAIL_FROM = os.environ.get('MAIL_FROM', 'contact@domexpire.fr')
MAIL_TO_ON_ERROR = [os.environ.get('MAIL_TO_ON_ERROR', 'contact@domexpire.fr')]
SMTP_HOST = 'localhost'


