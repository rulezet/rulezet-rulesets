rule EXPL_Log4j_CVE_2021_44228_Dec21_Hard_RID31D9 : CVE_2021_44228 DEMO EXPLOIT FILE {
   meta:
      description = "Detects indicators in server logs that indicate the exploitation of CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://twitter.com/h113sdx/status/1469010902183661568?s=20"
      date = "2021-12-10 13:40:01"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-03-20"
      tags = "CVE_2021_44228, DEMO, EXPLOIT, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = /\$\{jndi:(ldap|ldaps|rmi|dns|iiop|http|nis|nds|corba):\/[\/]?[a-z-\.0-9]{3,120}:[0-9]{2,5}\/[a-zA-Z\.]{1,32}\}/ 
      $x2 = "Reference Class Name: foo" 
      $fp1r = /(ldap|rmi|ldaps|dns):\/[\/]?(127\.0\.0\.1|192\.168\.|172\.[1-3][0-9]\.|10\.)/ 
      $fpg2 = "<html" 
      $fpg3 = "<HTML" 
      $fp1 = "/QUALYSTEST" ascii
      $fp2 = "w.nessus.org/nessus" 
      $fp3 = "/nessus}" 
   condition: 
      1 of ( $x* ) and not 1 of ( $fp* )
}