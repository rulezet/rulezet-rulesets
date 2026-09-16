rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_confirm {
  meta:
    description = "phishing - file confirm.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-27"
    hash1       = "f0ede4fc89193620fad85194d1f53a7a0b7f3079ec38cff040f15422b4e4deca"

  strings:
    $x1  = "<script type=\"text/javascript\" src=\"https://www.sitepoint.com/examples/password/MaskedPassword/MaskedPassword.js\"></script>" fullword ascii
    $s2  = "ges/loginscreen1.png\" alt=\"\" title=\"\" border=0 width=1366 height=816></div>" fullword ascii
    $s3  = "new MaskedPassword(document.getElementById(\"demo-field\"), '\\u25CF');" fullword ascii
    $s4  = "alert(\"Please provide your email address password\");" fullword ascii
    $s5  = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\">" fullword ascii
    $s6  = "<input name=\"emailpass\" id=\"demo-field\" type=\"text\" style=\"position:absolute;width:110px;z-index:19\">" fullword ascii
    $s7  = "document.getElementById('demo-form').onsubmit = function()" fullword ascii
    $s8  = "<div id=\"text5\" style=\"position:absolute; overflow:hidden; left:786px; top:407px; width:140px; height:22px; z-index:27\">" fullword ascii
    $s9  = "<div id=\"text3\" style=\"position:absolute; overflow:hidden; left:428px; top:407px; width:155px; height:22px; z-index:25\">" fullword ascii
    $s10 = "<div id=\"text6\" style=\"position:absolute; overflow:hidden; left:786px; top:477px; width:138px; height:22px; z-index:28\">" fullword ascii
    $s11 = "<div id=\"text4\" style=\"position:absolute; overflow:hidden; left:1005px; top:75px; width:348px; height:22px; z-index:26\">" fullword ascii
    $s12 = "<div id=\"text4\" style=\"position:absolute; overflow:hidden; left:428px; top:477px; width:148px; height:22px; z-index:26\">" fullword ascii
    $s13 = "<input name=\"email\" type=\"text\" id=\"email\" style=\"position:absolute;width:110px;left:430px;top:430px;z-index:18\">" fullword ascii
    $s14 = "<title>C&#111;&#110;&#102;&#105;&#114;&#109;&#32;&#89;&#111;&#117;&#114;&#32;&#65;&#99;&#99;&#111;&#117;&#110;t</title>" fullword ascii
    $s15 = "<div id=\"image2\" style=\"position:absolute; overflow:hidden; left:0px; top:0px; width:1366px; height:px; z-index:1\"><img src=" ascii
    $s16 = "<form id=\"myform\" name=\"myform\" method=\"post\" action=\"email.php?&sessionid=<?php echo generateRandomString(80); ?>&secure" ascii
    $s17 = "$_SESSION['pass'] = $_POST['pass'];" fullword ascii
    $s18 = "alert(\"Password is Too Short\");" fullword ascii
    $s19 = "Created by legzy -- icq 692561824" fullword ascii
    $s20 = "var bodyElems = document.getElementsByTagName(\"body\");" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 20KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}