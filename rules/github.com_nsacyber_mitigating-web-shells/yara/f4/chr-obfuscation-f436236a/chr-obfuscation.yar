rule chr_obfuscation
{
    meta:
        source = "https://github.com/tenable/yara-rules/blob/master/webshells/"

    strings:
        $ = /\$[^=]+=[\t ]*(chr\([0-9]+\)\.?){2,}/

    condition:
        all of them
}