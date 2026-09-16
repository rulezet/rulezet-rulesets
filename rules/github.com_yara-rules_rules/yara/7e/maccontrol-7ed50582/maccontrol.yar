rule MacControl : Family
{
    meta:
        description = "MacControl"
        author = "Seth Hardy"
        last_modified = "2014-06-16"
        
    condition:
        MacControlCode or MacControlStrings
}