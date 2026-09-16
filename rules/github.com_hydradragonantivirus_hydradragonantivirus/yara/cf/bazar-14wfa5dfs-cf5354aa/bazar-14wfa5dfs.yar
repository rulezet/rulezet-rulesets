import "pe"
rule bazar_14wfa5dfs {
  meta:
    description = "files - file 14wfa5dfs.exe"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-02-22"
    hash1       = "2065157b834e1116abdd5d67167c77c6348361e04a8085aa382909500f1bbe69"

  strings:
    $s1  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii  
    $s2  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii  
    $s3  = "AppPolicyGetProcessTerminationMethod" fullword ascii
    $s4  = "0??dfg.dll ASHI128 bit 98tqewC58752F9578" fullword ascii
    $s5  = "*http://crl4.digicert.com/assured-cs-g1.crl0L" fullword ascii
    $s6  = "*http://crl3.digicert.com/assured-cs-g1.crl00" fullword ascii
    $s7  = "/http://crl4.digicert.com/sha2-assured-cs-g1.crl0L" fullword ascii
    $s8  = "appguid={8A69D345-D564-463C-AFF1-A69D9E530F96}&iid={F61A86A8-0045-3726-D207-E8A923987AD2}&lang=ru&browser=4&usagestats=1&appname" ascii
    $s9  = "operator co_await" fullword ascii
    $s10 = "appguid={8A69D345-D564-463C-AFF1-A69D9E530F96}&iid={F61A86A8-0045-3726-D207-E8A923987AD2}&lang=ru&browser=4&usagestats=1&appname" ascii
    $s11 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
    $s12 = "Google LLC1" fullword ascii
    $s13 = "Google LLC0" fullword ascii
    $s14 = "Unknown issuer0" fullword ascii
    $s15 = "DigiCert, Inc.1$0\"" fullword ascii
    $s16 = "=Google%20Chrome&needsadmin=prefers&ap=x64-stable-statsdef_1&installdataindex=empty" fullword ascii
    $s17 = "TIMESTAMP-SHA256-2019-10-150" fullword ascii
    $s18 = "vggwqrwqr7d6" fullword ascii
    $s19 = "api-ms-win-core-file-l1-2-2" fullword wide  
    $s20 = "__swift_2" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and
    (pe.imphash() == "d8af53b239700b702d462c81a96d396c" and 8 of them)
}