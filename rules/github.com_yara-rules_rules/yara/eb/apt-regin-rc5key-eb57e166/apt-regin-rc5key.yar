rule apt_regin_rc5key 
{
    
    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect Regin RC5 decryption keys"
        version = "1.0"
        last_modified = "2014-11-18"
    
    strings:
        $key1={73 23 1F 43 93 E1 9F 2F 99 0C 17 81 5C FF B4 01}
        $key2={10 19 53 2A 11 ED A3 74 3F C3 72 3F 9D 94 3D 78}

    condition:
        any of ($key*)
}