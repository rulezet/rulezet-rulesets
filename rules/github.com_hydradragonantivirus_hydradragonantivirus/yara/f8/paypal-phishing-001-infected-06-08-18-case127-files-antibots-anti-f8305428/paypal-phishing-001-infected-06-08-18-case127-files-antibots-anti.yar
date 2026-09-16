rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_Antibots_anti {
  meta:
    description = "case127 - file anti.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "3b9405fcf832d194ee1d073d60079275e79942235c4fb773ab11c600201e07ea"

  strings:
    $s1  = "echo \"HELLO BITCH BOOTS YOU ARE LOCKED BY X-GHOST MA| I FUCKING LOVE YOU HAHAHHAHAHAHAHAHAHAHAHAH YLEH LOOOD T7OWA B L3RBIY" fullword ascii
    $s2  = "#       ||~ http://fb.com/profile.php?id=100013164673156 ~||       #" fullword ascii
    $s3  = "if (stripos($_SERVER['HTTP_USER_AGENT'],$word2)){" fullword ascii
    $s4  = "\"68.65.53.71\"," fullword ascii  
    $s5  = "\"192.comagent\"," fullword ascii
    $s6  = "\"searchprocess\"," fullword ascii
    $s7  = "\"inktomisearch.com\"," fullword ascii
    $s8  = "\"addthis.com\"," fullword ascii
    $s9  = "\"skymob.com\"," fullword ascii
    $s10 = "\"amagit.com\"," fullword ascii
    $s11 = "\"ah-ha.com\"," fullword ascii
    $s12 = "\"^212.150.*.*\"," fullword ascii  
    $s13 = "\"^64.233.160.*\"," fullword ascii  
    $s14 = "\"^66.207.120.*\"," fullword ascii  
    $s15 = "\"^212.143.*.*\"," fullword ascii  
    $s16 = "\"^217.132.*.*\"," fullword ascii  
    $s17 = "\"^212.235.*.*\"," fullword ascii  
    $s18 = "\"pgp key agent\"," fullword ascii
    $s19 = "if (preg_match('/' . $ip . '/',$_SERVER['REMOTE_ADDR'])) {" fullword ascii
    $s20 = "\"^216.239.32.*\"," fullword ascii  

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 30KB and
      (8 of them)
    ) or (all of them)
}