rule function_through_object {
    strings: 
        $ = "['eval']"
        $ = "['unescape']"
        $ = "['charCodeAt']"
        $ = "['fromCharCode']"
    condition: 
        any of them and filesize < 500KB
}