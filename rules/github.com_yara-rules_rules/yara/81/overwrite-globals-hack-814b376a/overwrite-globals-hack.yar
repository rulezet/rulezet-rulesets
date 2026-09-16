rule overwrite_globals_hack {
    strings: $ = /\$GLOBALS\['[^']{,20}'\]=Array\(/
    condition: any of them
}