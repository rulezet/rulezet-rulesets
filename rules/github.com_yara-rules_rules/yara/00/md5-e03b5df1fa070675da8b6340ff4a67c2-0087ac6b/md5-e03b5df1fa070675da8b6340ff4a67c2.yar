rule md5_e03b5df1fa070675da8b6340ff4a67c2 {
    strings:
        $ = /if\(preg_match\("\/onepage\|admin\/",\s*\$_SERVER\['REQUEST_URI'\]\)\)\{\s*@?file_put_contents/
        $ = /@?base64_encode\(serialize\(\$_REQUEST\)\."--"\.serialize\(\$_COOKIE\)\)\."\\n",\s*FILE_APPEND\)/
    condition: any of them
}