rule pwsh_getEnvironmentVariable
{
    meta:
        description = "Scripts detects environment variables"
        author = "k3rnelcallz"
        sha = "37c72ba7697589aac2275e9f44de1e821aa4ef8ad7b54f6db91339681457aec1"
        source = "mbazaar"
        creation_date = "12_10_25"
        modified_date = "12_10_25"
        category = "Info"
    
    strings:
        $g1 = "GetEnvironmentVariable('USERPROFILE'))" ascii
        $g2 = "GetEnvironmentVariable('TEMP'))" ascii
        $g3 = "GetEnvironmentVariable('TMP'))" ascii

    condition:
        any of ($g*)
}