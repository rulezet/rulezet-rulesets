rule fopo_obfuscator {
    strings:
        $ = "www.fopo.com.ar"
    condition: 
        any of them and filesize < 500KB
}