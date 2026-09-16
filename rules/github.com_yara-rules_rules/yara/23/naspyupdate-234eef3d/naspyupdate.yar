rule nAspyUpdate : Family
{
    meta:
        description = "nAspyUpdate"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
        
    condition:
        nAspyUpdateCode or nAspyUpdateStrings
}