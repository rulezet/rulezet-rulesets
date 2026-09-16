rule spam_mailer {
    strings:
        $ = "<strong>WwW.Zone-Org</strong>"
        $ = "echo eval(urldecode("
    condition: any of them
}