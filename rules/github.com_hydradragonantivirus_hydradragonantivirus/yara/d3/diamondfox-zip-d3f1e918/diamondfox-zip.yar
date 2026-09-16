rule diamondfox_zip

{

    meta:
        description = "Find zip archives of panels"
        author = "Brian Carter"
        last_modified = "March 31, 2017"
        
    strings:
        $txt1 = "gate.php"
        $txt2 = "install.php"
        $txt3 = "post.php"
        $txt4 = "plugins"
        $txt5 = "statistics.php"
        $magic = { 50 4b 03 04 }
        $not1 = "joomla" nocase
        
    condition:
        $magic at 0 and all of ($txt*) and not any of ($not*)
        
}