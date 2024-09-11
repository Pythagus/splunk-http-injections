#
# This file contains all the rules useful to 
# recognize the suspicious URL among the legitimate
# HTTP traffic.
#
# Author: Damien MOLINA
#

# This value is extremely useful to determine the date of the
# last update of the rules, so that we can only take the new rules
# into account if the client checked the new rules.
version = 1

#
# Local File Inclusion (LFI).
#
# As OWASP says, "Local file inclusion (also known as LFI) is the process of including files, 
# that are already locally present on the server, through the exploiting of vulnerable inclusion 
# procedures implemented in the application."
#
# Examples:
#      - http://example.org/?../../../../etc/passwd
#      - http://example.org/README.md
#      - http://example.org/vendor/laravel
#      - http://example.org/../../../database/master.db
#
# See: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
#
patterns_lfi = {
    # Directory traversal (Windows + Linux).
    "LFI_DIRECTORY_TRAVERSAL": r"(\/|\\|\%)+(\.)+(\/|\\|\%)+(\.)+",

    # Linux system files.
    "LFI_2": r"(^|\/)\.(ssh|git|bash|env|config|htaccess|htpasswd|composer|ansible|babel|composer|config|eslint|putty|idea|docker|appledb|xauthority|xdefaults|xresources|passwd)", # Hidden files/folders like .git
    "LFI_3": r"\b((boot|php|system|desktop|win)\.ini|httpd\.conf|(log|logs)(\/|\\)(access|error)(\.|\_)log)", # Sensitive files
    "LFI_4": r"(\b|\/|\\)(var|etc|usr|proc|logs)(\/|\\)+(log|www|mail|bin|lib|run|spool|local|self|httpd|apache|passwd|shadow|nginx|mysql|host|security|ssh|adm|cpanel|ports|sbin|([a-z0-9\-]+)(\.d|ftpd))", # Sensitive Linux folders
    "LFI_5": r"\.(pem|py|key|yml|sh|ppk|p12|conf|sqlite|sqlitedb|sql|db|sql\.\w+|tar|tar\.\w+|war|rar|7z|bz2|lz|swp)$", # Suspicious files that shouldn't be accessed via URL.

    # Other files.
    "LFI_WINDOWS_FILESYSTEM": r"\b(c|d):((\/|\\)|windows|users|program)", # Windows system files.
    "LFI_GIT_FILES": r"(^|\/|\\)(readme|changes|changelog|code_of_conduct|versioning|license|contributing)\.md", # Git files.
    "LFI_LIBRAIRY_FILES": r"^(\/|\\)*vendor(\/|\\)", # PHP librairy files.

    # Well-known folder scripts.
    # Examples:
    #  - /.well-known/mini.php
    #  - /.well-known/admin.php
    #  - /cgi-bin/admin.php
    "LFI_KNOWN_FOLDERS_SCRIPTS": r"(\.well-known|cgi-bin)(\/|\\)(.*)\.(php)",
}

#
# SQL Injection.
#
# Once again, OWASP mentions that "A SQL injection attack consists of insertion or “injection” 
# of a SQL query via the input data from the client to the application".
#
# Examples:
#      - http://example.org/?username=" OR 1=1
#      - http://example.org/?query=select * from users ;
#
# See: https://owasp.org/www-community/attacks/SQL_Injection
#
patterns_sqli = {
    "SQL_1": r"\b(or|and|having|where)(\s|:|\(|\"|\')*[0-9xya]+(\)|\"|\'|\s)*=+(\s|\(|\"|\')*[0-9axy]+", # AND/OR 1=1
    "SQL_2": r"\b(select|insert|update|delete|drop|alter|create|union|waitfor(\s+)delay|(order(\s+)by))\s+", # SQL keywords
    "SQL_3": r"\b(pg_sleep|benchmark|randomblob|sleep|concat|concat_ws|extractvalue|updatexml|tdesencrypt|md5|chr)(\s*)\(", # SQL functions
    "SQL_4": r"\b(or|and)((\s+)true|(.*)is(\s*)null)", # Arithmetic evaluation
    "SQL_5": r"\b(xp_cmdshell|xp_enumgroups|xp_grantlogin|xp_logevent|xp_logininfo|xp_msver|xp_revokelogin|xp_sprintf|xp_sqlmaint|xp_sscanf|xp_regread)", # Microsoft SQL server commands
    "SQL_6": r"\b(bin|ord|hex|char)(\s*)(\(|\[)", # SQL 'arithmetic' functions
}

#
# Cross Site Scripting (XSS).
#
# OWASP defines XSS attacks as "a type of injection, in which malicious scripts are injected into 
# otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application 
# to send malicious code, generally in the form of a browser side script, to a different end user".
#
# Examples:
#      - http://example.org/?username=alert("hello")
#      - http://example.org/?query=<script>alert(document.cookie)</script>
#      - http://example.org/?query=<script>top["al" + "ert"](document["cookie"])</   script >
#
# See: https://owasp.org/www-community/attacks/xss/
patterns_xss = {
    "XSS_1": r"<(\s*)script(\s*)", # <script> tags
    "XSS_2": r"\bon([a-z]+)(\s|=| |})", # Javascript keywords
    "XSS_3": r"\b(throw|alert|prompt)(\s*)(\s|{|\(|\)|\`)", # Some Javascript functions like alert(3)
    "XSS_4": r"\b(window|top)(\s*)\[[^\]]*\]", # Some javascript functions like top['alert']
    "XSS_5": r"\b(java|live|vb|j|w)script(\s*):", # Scripting languages
    "XSS_6": r"\b(document\.(domain|window|write|cookie|location)|response\.write)", # Document functions
    "XSS_FUNCTION_RENAME": r"\b[a-z]=[a-z]+,[a-z]\([^\)]*\)(\W|$)", # Function renaming like a=alert,a(1)
}

#
# Remote Code Execution (RCE).
#
# OWASP confirms that it is "an attack in which the goal is execution of arbitrary commands on the 
# host operating system via a vulnerable application". "The attacker extends the default functionality 
# of the application, which execute system commands, without the necessity of injecting code".
#
# Examples:
#      - http://example.org/?query=false; phpinfo()
#      - http://example.org/?redirect=http://mal.icious
#
# See: 
#      - https://owasp.org/www-community/attacks/Code_Injection
#      - https://owasp.org/www-community/attacks/Command_Injection
patterns_rce = {
    # HTTP redirections.
    "RCE_HTTP_1": r"\b(oast\.pro|oast\.live|oast\.site|oast\.online|oast\.fun|oast\.me|bxss\.me|interact\.sh|evil\.com|cirt\.net)", # Redirection to known malicious websites.
    
    # PHP code.
    "RCE_PHP_1": r"<\?php", # <?php
    "RCE_PHP_2": r"\b(phpinfo|phpversion|system|passthru|exec|shell_exec|backticks|base64_decode|sleep)(\s*)\(", # i.e. phpinfo()
    "RCE_PHP_3": r"\b\$\_(server|get|post|files|cookie|session|request|env|http_get_vars|http_post_vars)", # Global variables: https://www.php.net/manual/en/language.variables.superglobals.php
    "RCE_PHP_4": r"(bzip2|expect|glob|phar|ogg|rar|ssh2|zip|zlib|file|php):\/\/", # PHP local file wrapper.
    "RCE_PHP_COMMANDS_1": r"\ballow_url_(fopen|include)\W",

    # Java code.
    "RCE_JAVA_1": r"\bjava\.(io|lang|net|util)\.",

    # Bash code.
    "RCE_OS_1": r"\b(echo|nslookup|printenv|which|wget|curl|whoami|ping|uname|systeminfo|sysinfo|ifconfig|sleep|perl|netstat|ipconfig|nc|net(\s+)(localgroup|user|view)|netsh|dir|ls|pwd)(\s|{|\()",

    # Windows.
    "RCE_WINDOWS_1": r"(%systemroot%|hklm\\system\\)",
}

#
# Application-specific patterns.
#
# Some specific applications / framework / products define their own files,
# like WordPress defines ultiple wp-* files and folders. If your application
# is not based on one of this products, then you can enable the patterns associated.
#
patterns_custom_apps = {
    "WORDPRESS": {
        "specific_files": {
            "WORDPRESS_1": r"\bwp-[a-z\-]+(\/|\.php)"
        },
    },

    "LARAVEL": {
        "blacklist": {
            "LARAVEL_UNWANTED_PHP_FILES": r"^(?!index)\w+\.php$",
        }
    }
}

# Legitimate user agent regex.
pattern_user_agent = r"(API-Spyder|Cyberint|HTTP Banner Detection|Nacos|bitdiscovery|Nmap)"

# Legitimate X-Forwarded-For regex.
pattern_xff = r"^(((([0-9\.]{1,3}\.){3}[0-9]{1,3}|(?:\[)?[0-9a-f:]+(?:\])?)(?:\:[0-9]+)?)(,|,\s|$))+$"

# Legitimate Accept-Language values.
pattern_accept_language = r"^(((?:,\s*)?([a-zA-Z]{2}(?:-[a-zA-Z0-9]{2,3})?|\*)(?:;(\s*)q=[0-9](?:\.[0-9])?)?)+)$"

# Regex matching a legitimate asset URL like http://example.org/images/example.jpg
pattern_worthless_asset_url = r"^([a-zA-Z0-9\/\.]+)$"