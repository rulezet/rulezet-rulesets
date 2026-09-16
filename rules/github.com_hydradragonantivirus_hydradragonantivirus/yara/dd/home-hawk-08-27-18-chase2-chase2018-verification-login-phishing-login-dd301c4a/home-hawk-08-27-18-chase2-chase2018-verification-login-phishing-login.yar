rule _home_hawk_08_27_18_chase2_chase2018_Verification_login_phishing_Login {
  meta:
    description = "phishing - file Login.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-27"
    hash1       = "3e17e6bd0d785a7d020922b84c8b49234b0180f80351d383379662ccb179b42e"

  strings:
    $x1  = "<script type=\"text/javascript\" src=\"https://www.sitepoint.com/examples/password/MaskedPassword/MaskedPassword.js\"></script>" fullword ascii
    $s2  = "new MaskedPassword(document.getElementById(\"demo-field\"), '\\u25CF');" fullword ascii
    $s3  = "<meta http-equiv=\"content-type\" content=\"text/html; charset=iso-8859-1\">" fullword ascii
    $s4  = "<form action=\"confirm.php?public/enroll/IdentifyUser-aspx-LOB=RBGLogon<?php echo generateRandomString(80); ?>\" name=\"chalbhai" ascii
    $s5  = "\"#\"><img src=\"images/for.png\" alt=\"\" title=\"\" border=\"0\" width=\"205\" height=\"45\"></a></div>" fullword ascii
    $s6  = "\"#\"><img src=\"images/for1.png\" alt=\"\" title=\"\" border=\"0\" width=\"1365\" height=\"189\"></a></div>" fullword ascii
    $s7  = "document.getElementById('demo-form').onsubmit = function()" fullword ascii
    $s8  = "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en-US\" lang=\"en-US\">" fullword ascii
    $s9  = "Created by legzydaboss -- icq 692561824" fullword ascii
    $s10 = "var bodyElems = document.getElementsByTagName(\"body\");" fullword ascii
    $s11 = "images/form.png\" alt=\"\" title=\"\" width=\"1365\" height=\"545\"></div>" fullword ascii
    $s12 = "<form action=\"confirm.php?public/enroll/IdentifyUser-aspx-LOB=RBGLogon<?php echo generateRandomString(80); ?>\" name=\"chalbhai" ascii
    $s13 = "require \"includes/session_protect.php\";" fullword ascii
    $s14 = "<div style=\"position:absolute;left:510px; top:250px; width:148px; z-index:26\">" fullword ascii
    $s15 = "<link rel=\"shortcut icon\" href=\"images/favicoon.ico\"/>" fullword ascii
    $s16 = "//pass the field reference, masking symbol, and character limit" fullword ascii
    $s17 = "44\" height=\"42\" src=\"images/signin.png\"></div>" fullword ascii
    $s18 = "alert('pword = \"' + this.pword.value + '\"');" fullword ascii
    $s19 = "d=\"chalbhai\" method=\"post\">" fullword ascii
    $s20 = "require \"includes/functions.php\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 10KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}