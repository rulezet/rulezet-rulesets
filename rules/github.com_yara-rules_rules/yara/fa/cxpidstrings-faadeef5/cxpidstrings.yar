rule cxpidStrings
{
    meta:
        description = "cxpid Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
        
    strings:
        $ = "/cxpid/submit.php?SessionID="
        $ = "/cxgid/"
        $ = "E21BC52BEA2FEF26D005CF"
        $ = "E21BC52BEA39E435C40CD8"
        $ = "                   -,L-,O+,Q-,R-,Y-,S-"
        
    condition:
       any of them
}