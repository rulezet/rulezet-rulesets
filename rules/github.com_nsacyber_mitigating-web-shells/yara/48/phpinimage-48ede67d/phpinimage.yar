rule phpInImage
{
    meta:
        source = "Vlad https://github.com/vlad-s"

    strings:
        $php_tag = "<?php"
        $gif = {47 49 46 38 ?? 61}         $jfif = { ff d8 ff e? 00 10 4a 46 49 46 }
        $png = { 89 50 4e 47 0d 0a 1a 0a }
        $jpeg = {FF D8 FF E0 ?? ?? 4A 46 49 46 } 

    condition:
        (($gif at 0) or ($jfif at 0) or ($png at 0) or ($jpeg at 0)) and $php_tag
}