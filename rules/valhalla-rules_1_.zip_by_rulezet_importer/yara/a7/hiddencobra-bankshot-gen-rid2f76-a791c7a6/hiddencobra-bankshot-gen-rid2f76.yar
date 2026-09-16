rule HiddenCobra_BANKSHOT_Gen_RID2F76 : DEMO EXE FILE G0032 GEN MAL NK {
   meta:
      description = "Detects Hidden Cobra BANKSHOT trojan"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"
      date = "2017-12-26 11:58:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-06-10"
      hash1 = "89775a2fbb361d6507de6810d2ca71711d5103b113179f1e1411ccf75e6fc486"
      hash2 = "8b2d084a8bb165b236d3e5436d6cb6fa1fda6431f99c4f34973dc735b4f2d247"
      hash3 = "b766ee0f46c92a746f6db3773735ee245f36c1849de985bbc3a37b15f7187f24"
      tags = "DEMO, EXE, FILE, G0032, GEN, MAL, NK"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" fullword wide
      $s2 = "rHTTP/1.1 200 Connection established" fullword wide
      $s3 = "Proxy-Connection: keep-alive" fullword wide
      $s4 = "\\msncf.dat" wide
      $s5 = "msvcru32.bat" fullword ascii
      $s6 = "reg delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"%s\" /f" fullword ascii
      $s7 = "MXINFO.DLL" fullword ascii
      $s8 = "usrvc32.bat" fullword ascii
      $s9 = "ping -n 1 127.0.0.1" fullword ascii
      $s10 = "%sd.e%sc \"%s > %s 2>&1\"" ascii fullword
      $s11 = "DWS*.tmp" ascii fullword
      $s12 = "CS*.tmp" fullword wide
      $s13 = "WM*.tmp" fullword wide
      $x1 = "CgpaipIddwspwe32Hnaehsdi" fullword ascii
      $x2 = "RpiPmtiCdopIsgpao" fullword ascii
      $x3 = "RpiLtnodlhOtgpcidgyA" fullword ascii
      $x4 = "LatiQdgHtnrwpDbupci" fullword ascii
      $x6 = "\\system32\\msncf.dat" ascii
      $x7 = "GprthipgHpgktcpCigwSanowpgA" fullword ascii
      $a1 = "live.dropbox.com" fullword ascii
      $a2 = "tatadocomo.yahoo.com" fullword ascii
      $a3 = "widgets.twimg.com" fullword ascii
      $a4 = "history.paypal.com" fullword ascii
      $a5 = "www.bitcoin.org" fullword ascii
      $a6 = "web.whatsapp.com" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and ( 1 of ( $x* ) or 2 of ( $s* ) or 4 of ( $a* ) )
}