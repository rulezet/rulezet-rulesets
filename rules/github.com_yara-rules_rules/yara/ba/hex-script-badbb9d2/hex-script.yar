rule hex_script {
    strings:
        $ = "\\x73\\x63\\x72\\x69\\x70\\x74\\x22"
    condition: 
        any of them and filesize < 500KB
}