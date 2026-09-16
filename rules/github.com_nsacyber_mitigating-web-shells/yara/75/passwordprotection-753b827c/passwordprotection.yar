rule passwordProtection
{
    meta:
        source = "https://github.com/nbs-system/php-malware-finder"
        
    strings:
        $md5 = /md5\s*\(\s*\$_(GET|REQUEST|POST|COOKIE|SERVER)[^)]+\)\s*===?\s*['"][0-9a-f]{32}['"]/ nocase
        $sha1 = /sha1\s*\(\s*\$_(GET|REQUEST|POST|COOKIE|SERVER)[^)]+\)\s*===?\s*['"][0-9a-f]{40}['"]/ nocase
    condition:
        (any of them) 
}