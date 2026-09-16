rule PAYPAL_PHISHING_001_infected_06_08_18_case127_pfr {
  meta:
    description = "case127 - file pfr.zip"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "72f57bb63927967259bbc740d1dce85f1bdb99458933a9d91e164d02051fa216"

  strings:
    $s1  = "files/my/ID/identity/css/themes/jquery.filer-dragdropbox-theme.css" fullword ascii
    $s2  = "files/css/paypal_logo_center.png" fullword ascii
    $s3  = "files/my/ID/identity/images/ppcom_monogram.svg}V" fullword ascii
    $s4  = "files/file/template.css" fullword ascii
    $s5  = "files/css/themes/jquery.filer-dragdropbox-theme.css" fullword ascii
    $s6  = "files/css/peek-shield-logo.png" fullword ascii
    $s7  = "files/images/logo.png}Vy8T{" fullword ascii
    $s8  = "files/my/ID/identity/images/ppcom_monogram.svg" fullword ascii
    $s9  = "files/my/ID/identity/assets/fonts/jquery.filer-icons/jquery-filer.svg" fullword ascii
    $s10 = "files/my/ID/identity/assets/fonts/jquery.filer-icons/jquery-filer.ttf" fullword ascii
    $s11 = "files/my/ID/identity/assets/fonts/jquery.filer-icons/jquery-filer.css" fullword ascii
    $s12 = "files/my/ID/identity/assets/fonts/jquery.filer-icons/jquery-filer.eot" fullword ascii
    $s13 = "files/img/logo.png" fullword ascii
    $s14 = "files/images/logo.png" fullword ascii
    $s15 = "files/css/authflow_illustrations.png" fullword ascii
    $s16 = "files/my/ID/identity/images/ppcom.svg" fullword ascii
    $s17 = "files/javascript/jquery-1.11.2.min.js" fullword ascii
    $s18 = "files/css/peek-shield-logo.pnguW" fullword ascii
    $s19 = "r3zult/index.txt" fullword ascii
    $s20 = "files/my/ID/identity/assets/fonts/jquery.filer-icons/jquery-filer-preview.html" fullword ascii

  condition:
    (uint16(0) == 0x4b50 and
      filesize < 3000KB and
      (8 of them)
    ) or (all of them)
}