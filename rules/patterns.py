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
pattern_lfi = {
    # Directory traversal (Windows + Linux).
    "LFI_1": r"(\/|\\)+(\.)+(\/|\\)+(\.)+",

    # Linux system files.
    "LFI_2": r"(^|\/)\.(ssh|git|bash|env|config|htaccess|htpasswd|composer|ansible|babel|composer|config|eslint|putty|idea|docker|appledb|xauthority|xdefaults|xresources)", # Hidden files/folders like .git
    "LFI_3": r"(\W|)((boot|php|system|desktop|win)\.ini|httpd\.conf|(\/|\\)(log|logs)(\/|\\)(access|error)(\.|\_)log)", # Sensitive files
    "LFI_4": r"(\W|)(var|etc|usr|proc|logs)(\/|\\)+(log|www|mail|bin|lib|run|spool|local|self|httpd|apache|passwd|shadow|nginx|mysql|host|security|ssh|adm|cpanel|ports|sbin|([a-z0-9\-]+)(\.d|ftpd))", # Sensitive Linux folders
    "LFI_5": r"\.(pem|py|key|yml|sh|ppk|p12|conf|sqlite|sqlitedb|sql|db|sql\.\w+|tar|tar\.\w+|war|rar|7z|bz2|lz|swp)$", # Suspicious files that shouldn't be accessed via URL.

    # Other files.
    "LFI_6": r"(\W|)(c|d):(\/|\\)", # Windows system files.
    "LFI_7": r"\/(readme|changes|changelog|code_of_conduct|versioning|license|contributing)\.md", # Git files.
    "LFI_8": r"^(?:\/)?vendor(\/|\\)", # PHP librairy files.
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
pattern_sqli = {
    "SQL_1": r"(\W|)(or|and|having|where)(\s+)((\(|\"|\')*)([0-9xy]+)((\)|\"|\')*)=((\(|\"|\')*)([0-9xy]+)", # AND/OR 1=1
    "SQL_2": r"(\W|)(select|insert|update|delete|drop|alter|create|union|waitfor(\s+)delay|(order(\s+)by))\s+", # SQL keywords
    "SQL_3": r"(\W|)(pg_sleep|benchmark|randomblob|sleep|concat|concat_ws|extractvalue|updatexml|tdesencrypt|md5|chr)(\s*)\(", # SQL functions
    "SQL_4": r"(\W|)(or|and)(\s+)true", # Arithmetic evaluation
    "SQL_5": r"(\W|)(xp_cmdshell|xp_regread)", # Microsoft SQL server commands
    "SQL_6": r"(\W|)(bin|ord|hex|char)[^a-z0-9\/]", # SQL 'arithmetic' functions
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
pattern_xss = {
    "XSS_1": r"<(\s*)script(\s*)", # <script> tags
    "XSS_2": r"(\W|)on([a-z]+)(\s|=| |})", # Javascript keywords
    "XSS_3": r"(\W|)(throw|alert|prompt)(\s*)(\s|{|\(|\)|\`)", # Some Javascript functions like alert(3)
    "XSS_4": r"(\W|)(window|top)(\s*)\[[^\]]*\]", # Some javascript functions like top['alert']
    "XSS_5": r"(\W|)(java|live|vb|j|w)script(\s*):", # Scripting languages
    "XSS_6": r"(\W|)(document\.(domain|window|write|cookie|location)|response\.write)", # Document functions
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
pattern_rce = {
    # HTTP redirections.
    "RCE_HTTP_1": r"\b(oast\.pro|oast\.live|oast\.site|oast\.online|oast\.fun|oast\.me|bxss\.me|interact\.sh|evil\.com|cirt\.net)", # Redirection to known malicious websites.
    
    # PHP code.
    "RCE_PHP_1": r"<\?php", # <?php
    "RCE_PHP_2": r"(\W|)(phpinfo|phpversion|system|passthru|exec|shell_exec|backticks|base64_decode|sleep)(\s*)\(", # i.e. phpinfo()
    "RCE_PHP_3": r"(\W|)\$\_(server|get|post|files|cookie|session|request|env|http_get_vars|http_post_vars)", # Global variables: https://www.php.net/manual/en/language.variables.superglobals.php
    "RCE_PHP_4": r"(bzip2|expect|glob|phar|ogg|rar|ssh2|zip|zlib|file|php):\/\/", # PHP local file wrapper.

    # Java code.
    "RCE_JAVA_1": r"\bjava\.(io|lang)\.",

    # Bash code.
    "RCE_OS_1": r"(\W|)(echo|nslookup|printenv|which|wget|curl|whoami|ping|uname|systeminfo|sysinfo|ifconfig|sleep|perl|netstat|ipconfig|nc|net(\s+)(localgroup|user|view)|netsh|dir|ls|pwd)\b",

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
        "whitelist": [
            r"\bwp-[a-z\-]+(\/|\.php)"
        ],
    },

    "LARAVEL": {
        "blacklist": [
            r"^(?!index)\w+\.php$",
        ]
    }
}

# Legitimate user agent regex.
pattern_user_agent = r"(API-Spyder|Cyberint|HTTP Banner Detection|Nacos|bitdiscovery|Nmap)"

# Legitimate X-Forwarded-For regex.
pattern_xff = r"^(((([0-9\.]{1,3}\.){3}[0-9]{1,3}|(?:\[)?[0-9a-f:]+(?:\])?)(?:\:[0-9]+)?)(,|,\s|$))+$"

# Legitimate Accept-Language values.
pattern_accept_language = r"^(((?:,\s*)?([a-zA-Z]{2}(?:-[a-zA-Z]{2})?|\*)(?:;(\s*)q=[0-9]\.[0-9])?)+)$"

pattern_worthless_asset_url = r"^([a-zA-Z0-9\/\-\._]+)$"