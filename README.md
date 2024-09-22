# Splunk - Detect HTTP injections
This Splunk app' is meant to detect HTTP injections (XSS, SQLi, RCE, etc.) among your legitimate traffic.

**Disclaimer:** this is not meant to be exhaustive. We only want to detect the basic injections and, of course, as much as possible. But if a special case is not detected as malicious, that doesn't matter.

- [Installation](#installation)
- [Configuration](#configuration)
    - [Update rules](#configuration-update-rules)
    - [Custom rules](#configuration-custom-rules)
    - [Disable a rules](#configuration-disable-rule)

# <a id="installation">#</a> Installation
Install this app as any other one, downloading the code through the Splunk Base.

After the installation, the app doesn't have any rules configured. Please, follow the [Update rules](#configuration-update-rules) section of this README to set your first rules.

**Interesting things to know:**
- This app comes with a KV-store named "HttpInjections_Rules"
- The command `checkinjection` will be callable by any Splunk user (check `metadata/default.meta`)


# <a id="configuration">#</a> Configuration

## <a id="configuration-update-rules">#</a> Update rules
The rules are storred in the `HttpInjections_Rules` KV-store in an encoded-format. You can configure your own rules based on your specific infrastructure (see the [Custom rules](#configuration-custom-rules) section).

To get the rules I developed:
- Copy the rules from the Github repository: [Pythagus/splunk-http-injectons/rules/compiled](https://github.com/Pythagus/splunk-http-injections/blob/main/rules/compiled)
- Open the "HTTP injections - Manage rules" dashboard (id: `http_injections_manage_rules`)
    - Set "Mode" input to "Update"
    - Paste the rules into the "Rules" input

## <a id="configuration-custom-rules">#</a> Custom rules
You can configure your own rules based on what you have on your infrastructure.

**Note:** Do not hesitate to share your updates of the rules / custom rules by opening an issue or a discussion. I'll be happy to merge your rules!

### Write a rule
First step is to right a Python regex matching the things that you know malicious. [regex101.com](https://regex101.com/) is a great tool to test regexes.

You will need to "identify" your rule with:
- a `rule_id` identifying what your rule tries to detect.
- a `rule_type`. For custom rules, please set this value to `CUSTOM`, so that your rule is not removed by the "Manage rules" dashboard updates.
- a `status`: 0 for disabling for rule, 1 for activating it.
- an `auto_update` value. This field won't have any effect for custom rules.


### Add the rule in Splunk
You can define new rules by inserting new raws in the `HttpInjections_Rules` KV-store. You will need admin rights to do that (unless you updated the `metadata/local.meta` file).

Don't forget to encode your rule in an hexadecimal format. You can encode you rule with the following Python code:
```python
encoded_rule = r"your rule".encode("utf-8").hex()
```

You can decode a rule with:
```python
decoded_rule = bytes.fromhex("encoded rule")
```

Or decode with Splunk:
```splunk
| eval decoded_rule = urldecode(replace(encoded_rule, "([a-f0-9]{2})","%\1"))
```

## <a id="configuration-disable-rule">#</a> Disable a rule