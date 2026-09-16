rule webshell_php_generic_backticks__converted_for_hunting: WEBSHELL HUNT_CONVERTED {
  meta:
    key   = "Generic PHP webshell which uses backticks directly on user input"
    key   = "https://creativecommons.org/licenses/by-nc/4.0/"
    key   = "Arnim Rupp"
    key   = "2021/01/07"
    score = 40

  strings:
    $backtick  = /`[\t ]*\$(_POST\[|_GET\[|_REQUEST\[|_SERVER\['HTTP_)/ wide ascii
    $php_short = "<?" wide ascii
    $no_xml1   = "<?xml version" nocase wide ascii
    $no_xml2   = "<?xml-stylesheet" nocase wide ascii
    $no_asp1   = "<%@LANGUAGE" nocase wide ascii
    $no_asp2   = /<script language="(vb|jscript|c#)/ nocase wide ascii
    $no_pdf    = "<?xpacket"
    $php_new1  = /<\?=[^?]/ wide ascii
    $php_new2  = "<?php" nocase wide ascii
    $php_new3  = "<script language=\"php" nocase wide ascii

  condition:
    ((($php_short in (0..100) or $php_short in (filesize - 1000..filesize)) and not any of ($no_*)) or any of ($php_new*)) and $backtick and (filesize >= 200 and filesize < 600
    )

}