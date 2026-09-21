import "pe"
rule case_26364_qwe {
   meta:
      description = "Case 26364 - file qwe.exe BlackSuit ransomware binary"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/08/26/blacksuit-ransomware/"
      date = "2024-08-20"
      hash1 = "60dcbfb30802e7f4c37c9cdfc04ddb411060918d19e5b309a5be6b4a73c8b18a"
   strings:
      $s1 = "<requestedExecutionLevel level = 'asInvoker' uiAccess = 'false' />" fullword ascii
      $s2 = "readme.blacksuit.txt" fullword wide
      $s3 = "---END RSA PUBLIC KEY-----" fullword ascii
      $s4 = "Q0ZkwAQVIbDNhXd1WM0sgajkBlDCqo7/xN1J8tdN5RH7njgltu9TlY2D4/c//70IYfCi4SYUVCSpUiVec6b6crv//bwXa489J9e8iruZ0jfZ+A/+31QXqNm3vGGeExZh" ascii
      $s5 = "ugHzziMZidFzMjw/sBynX5F60q6cE/xQnLXsT03ku6uj9klgIqE58A5+5jxLCLU7NWouX6OIMRsK2jkyOIaeWmT2s5z76PaBebSracTWUedtZ2qz62U7PwqherErP16s" ascii
      $s6 = "FN81uoDozfxgUonhHA6TuD/iVHluiuZhwFt0OnFAhpqSJnLJsSWmce3rUwxpvKO2G8JQpNl63tIn0BTvVyz2OQ0QB4eZsq5WuYOPW0YIE5nCxzzDNRH49KL8BCw5TpIP" ascii
      $s7 = "nYm3jVJI5fY4IOIbbKpVJ0mJdkcyAbaBXekA33COOE3FVSL/k4WkYKsbXVumq7Z2xfHff1Q9KlhA1PaWP6vVPlQvXSKdZYUMcSStOce3RuYh2FBfVo7yWMMp0M6hTTC2" ascii
      $s8 = "-----BEGIN RSA PUBLIC KEY-----MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAre9g2v/YKJF5okac0aAy5iLq0A3bwH4je29tFyrN1mkhp0zafxMuNn" ascii
      $s9 = "-----BEGIN RSA PUBLIC KEY-----MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAre9g2v/YKJF5okac0aAy5iLq0A3bwH4je29tFyrN1mkhp0zafxMuNn" ascii
      $s10 = ".rdata$voltmd" fullword ascii
      $s11 = "D$lfff" fullword ascii 
      $s12 = "l$|9D$ " fullword ascii
      $s13 = "2'2-252H2R2X2i2t2z2" fullword ascii
      $s14 = ";*<5<;<R<X<" fullword ascii
      $s15 = "021G1S3{3" fullword ascii
      $s16 = "92:U:p:" fullword ascii
      $s17 = "hCW,tf" fullword ascii
      $s18 = "727C7q7" fullword ascii
      $s19 = "=1]1|1" fullword ascii
      $s20 = "2(252:2" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      ( pe.imphash() == "ecc488e51fbb2e01a7aac2b35d5f10bd" or 8 of them )
}