rule obfuscated_globals {
    
    strings: $ = /\$GLOBALS\['.{1,10}'\] = "\\x/
    condition: any of them
}