#!/bin/bash

# 1. Generate RSA Keys for Nginx
# 2. Generate RSA Keys for Logstash
# 3. Ldap configuration

HERA_CONFIGURATION_FOLDER="/etc/hera"
NGINX_SSL_FOLDER="${HERA_CONFIGURATION_FOLDER}/nginx/ssl"
LOGSTASH_SSL_FOLDER="${HERA_CONFIGURATION_FOLDER}/logstash/ssl"
NGINX_INCLUDES_FOLDER="${HERA_CONFIGURATION_FOLDER}/nginx/includes"
AUTH_CONFIGURATION_FILE="${NGINX_INCLUDES_FOLDER}/auth"

HOSTNAME=$1

if [ -z "$HOSTNAME" ]; then
    echo "Please pass the hostname in argument"
    exit 1
fi

generateNginxCertificate() {
    echo "Generating certificate for Nginx..."
    mkdir -p $NGINX_SSL_FOLDER/private/ $NGINX_SSL_FOLDER/certs/
    openssl req -x509 -batch -nodes -newkey rsa:2048 -keyout $NGINX_SSL_FOLDER/private/nginx.key -out $NGINX_SSL_FOLDER/certs/nginx.crt -days 3650
}

generateLogstashCertificate() {
    echo "Generating certificate for Logstash..."
    mkdir -p /etc/hera/logstash/ssl/private/ /etc/hera/logstash/ssl/certs/
    openssl req -x509 -batch -nodes -newkey rsa:2048 -keyout $LOGSTASH_SSL_FOLDER/private/logstash-forwarder.key -out $LOGSTASH_SSL_FOLDER/certs/logstash-forwarder.crt -days 3650 -subj /CN=$HOSTNAME
}

generateAuthenticationConfiguration() {
    mkdir -p $NGINX_INCLUDES_FOLDER
    touch $AUTH_CONFIGURATION_FILE
    echo "What kind of authentication do you want? [basic/ldap/None]"
    read authenticationType
    if [ "$authenticationType" == "ldap" ]; then
        generateLdapConfiguration
    elif [ "$authenticationType" == "basic" ]; then
        generateBasicAuthConfiguration
    fi
}

generateBasicAuthConfiguration() {
    read -p "Enter the username you want to use: " username
    stty -echo
    read -p "Enter the associated password: " password
    stty echo
    echo "Done"
    buildBasicAuthConfigurationContent $username $password > $AUTH_CONFIGURATION_FILE
}

generateLdapConfiguration() {
    read -p "Enter your LDAP server URL: " ldapServerUrl
    read -p "Enter your service LDAP account domain: " ldapServiceAccountDomain
    read -p "Enter your service LDAP account name: " ldapServiceAccountName
    stty -echo
    read -p "Enter your service LDAP account password: " ldapServiceAccountPassword
    stty echo
    echo "Done"
    buildLdapConfigurationContent $ldapServerUrl $ldapServiceAccountDomain $ldapServiceAccountName $ldapServiceAccountPassword > $AUTH_CONFIGURATION_FILE
}

buildLdapConfigurationContent() {
    echo "ldap_server default {
  url '${1}';
  require valid_user;
  binddn '${2}\\\\${3}';
  binddn_passwd '${4}';
}
auth_ldap 'Please enter your LDAP credentials';
auth_ldap_servers default;
auth_ldap_cache_enabled on;
auth_ldap_cache_expiration_time 10000;
auth_ldap_cache_size 1000;"
}

buildBasicAuthConfigurationContent() {
    htpasswd -cb ${NGINX_INCLUDES_FOLDER}/.htpasswd $1 $2
    echo "auth_basic \"Restricted\";
auth_basic_user_file /etc/nginx/includes/.htpasswd;"
}

main() {
    if [ ! -e $HERA_CONFIGURATION_FOLDER ]; then
        generateNginxCertificate
        generateLogstashCertificate
        generateAuthenticationConfiguration
    else
        echo "Hera configuration folder already exists."
        return 1
    fi
}

main
