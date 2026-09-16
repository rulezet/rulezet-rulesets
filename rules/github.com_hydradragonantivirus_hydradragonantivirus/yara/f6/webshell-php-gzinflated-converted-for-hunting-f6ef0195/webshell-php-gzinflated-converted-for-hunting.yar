rule webshell_php_gzinflated__converted_for_hunting: WEBSHELL HUNT_CONVERTED {
  meta:
    key   = "PHP webshell which directly eval()s obfuscated string"
    key   = "https://creativecommons.org/licenses/by-nc/4.0/"
    key   = "Arnim Rupp"
    key   = "2021/01/12"
    score = 40

  strings:
    $payload2  = /eval\s?\(\s?("\?>".)?gzinflate\s?\(\s?base64_decode\s?\(/ wide ascii nocase
    $payload4  = /eval\s?\(\s?("\?>".)?gzuncompress\s?\(\s?(base64_decode|gzuncompress)/ wide ascii nocase
    $payload6  = /eval\s?\(\s?("\?>".)?gzdecode\s?\(\s?base64_decode\s?\(/ wide ascii nocase
    $payload7  = /eval\s?\(\s?base64_decode\s?\(/ wide ascii nocase
    $payload8  = /eval\s?\(\s?pack\s?\(/ wide ascii nocase
    $fp1       = "YXBpLnRlbGVncmFtLm9"
    $gfp1      = "eval(\"return [$serialised_parameter"
    $gfp2      = "$this->assert(strpos($styles, $"
    $gfp3      = "$module = new $_GET['module']($_GET['scope']);"
    $gfp4      = "$plugin->$_POST['action']($_POST['id']);"
    $gfp5      = "$_POST[partition_by]($_POST["
    $gfp6      = "$object = new $_REQUEST['type']($_REQUEST['id']);"
    $gfp7      = "The above example code can be easily exploited by passing in a string such as"
    $gfp8      = "Smarty_Internal_Debug::start_render($_template);"
    $gfp9      = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
    $gfp10     = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
    $gfp11     = "(eval (getenv \"EPROLOG\")))"
    $gfp12     = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
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
    (filesize >= 700KB and filesize < 2100KB
    )
    and not (any of ($gfp*)) and
    ((($php_short in (0..100) or $php_short in (filesize - 1000..filesize)) and not any of ($no_*)) or any of ($php_new*)) and 1 of ($payload*) and not any of ($fp*)
}