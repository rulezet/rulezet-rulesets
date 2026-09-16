rule Hpack
{
    meta:
        source = "https://github.com/nbs-system/php-malware-finder"
        
    strings:
        $globals = "474c4f42414c53" nocase
        $eval = "6576616C28" nocase
        $exec = "65786563" nocase
        $system = "73797374656d" nocase
        $preg_replace = "707265675f7265706c616365" nocase
        $base64_decode = "61736536345f6465636f646528677a696e666c61746528" nocase
    
    condition:
        any of them
}