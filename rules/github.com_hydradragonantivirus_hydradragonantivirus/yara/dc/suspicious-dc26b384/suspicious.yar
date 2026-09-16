rule suspicious {
  meta:
    description = "case127 - file suspicious.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "2ac349b726e19c04c50d3ef33f676848364f8f5f5be70b62604e6f3c35fc6104"

  strings:
    $s1  = "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js\" integrity=\"sha512-K1qjQ+NcF2TYO/eI3M6v8EiN" fullword ascii
    $s2  = "<script src=\"http://code.jquery.com/jquery-2.1.4.min.js\"></script>" fullword ascii
    $s3  = "<p>En cliquant sur continuer, vous confirmez que vous &ecirc;tes le propri&eacute;taire de ce compte.</p>" fullword ascii
    $s4  = "<a href=\"Billing.php?data=billing&execution=<?php echo md5('WorldOfHack'); ?>\" class=\"bt" fullword ascii
    $s5  = "<p>En cliquant sur continuer, vous confirmez que vous &ecirc;tes le propri&eacute;taire de c" fullword ascii
    $s6  = "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js\" integrity=\"sha512-K1qjQ+NcF2TYO/eI3M6v8EiNY" ascii
    $s7  = "Pour prot&eacute;ger votre compte, nous recherchons r&eacute;guli&egrave;rement des signe" fullword ascii
    $s8  = "<h4 class=\"big-title\">L'acc&egrave;s &agrave; votre compte est restreint pour des raisons de s&eacute;curit&eacute;.</h4>" fullword ascii
    $s9  = "<img src=\"css/peek-shield-logo.png\">" fullword ascii
    $s10 = "YZfA95pQumfvcVrTHtwQVDG+aHRqLi/ETn2uB+1JqwYqVG3LIvdm9lj6imS/pQ==\" crossorigin=\"anonymous\">" fullword ascii
    $s11 = "Apr&egrave;s avoir confirm&eacute; votre identit&eacute;, nous examinerons vos informations et" fullword ascii
    $s12 = "<h4 class=\"big-title\">L'acc&egrave;s &agrave; votre compte est restreint pour des raison" fullword ascii
    $s13 = "<label class=\"loginmarker\">" fullword ascii
    $s14 = "<meta name=\"robots\" content=\"noindex\" />" fullword ascii
    $s15 = "<link href=\"style.css\" rel=\"stylesheet\" type=\"text/css\">" fullword ascii
    $s16 = "restaurerons l'acc&egrave;s &agrave; votre compte." fullword ascii
    $s17 = "s pr&eacute;coces d'activit&eacute;s potentiellement frauduleuses." fullword ascii
    $s18 = "<link rel=\"icon\" href=\"css/fav.ico\" />" fullword ascii
    $s19 = "<a href=\"Billing.php?data=billing&execution=<?php echo md5('WorldOfHack'); ?>\" class=\"btn btnPremary\" style=\"width: 200px;" ascii

  condition:
    (uint16(0) == 0xbbef and
      filesize < 10KB and
      (8 of them)
    ) or (all of them)
}