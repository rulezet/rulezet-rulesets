rule md5_b3ee7ea209d2ff0d920dfb870bad8ce5 {
    strings:
        $ = /\$mysql_key\s*=\s*@?base64_decode/
        $ = /eval\(\s*\$mysql_key\s*\)/
    condition: all of them
}