import "pe"
rule Sliver_Implant_32bit
{
  meta:
    description = "Sliver 32-bit implant (with and without --debug flag at compile)"
    hash =  "911f4106350871ddb1396410d36f2d2eadac1166397e28a553b28678543a9357"
    author = "gssincla@google.com"
    reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
    date = "2022-11-18"
    modified = "2025-03-21"

    id = "6bc4d7d1-64cf-5920-8f07-54a8a7a94f26"
  strings:
    
        
    $s_tcppivot = { 81 ?? 74 63 70 70 [2-20] 81 ?? 04 69 76 6F 74  }

        
    $s_wg = { 66 81 ?? 77 67 }

        
    $s_dns = { 66 81 ?? 64 6E [2-20] 80 ?? 02 73 }

        
    $s_http = { 81 ?? 68 74 74 70 }

        
    $s_https = { 81 ?? 68 74 74 70 [2-20] 80 ?? 04 73 }

        
    $s_mtls = { 81 ?? 6D 74 6C 73 }

    $fp1 = "cloudfoundry" ascii fullword
    $fp2 = "googleapi.Error" ascii
  condition:
    4 of ($s*) 
    and not 1 of ($fp*)
    and not pe.number_of_signatures > 0
}