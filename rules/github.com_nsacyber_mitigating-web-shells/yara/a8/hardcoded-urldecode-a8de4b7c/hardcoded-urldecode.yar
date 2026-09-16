rule hardcoded_urldecode
{
    meta:
        source = "https://github.com/tenable/yara-rules/blob/master/webshells/"

    strings:
        $ = /urldecode[\t ]*\([\t ]*'(%[0-9a-fA-F][0-9a-fA-F])+'[\t ]*\)/

    condition:
        all of them
}