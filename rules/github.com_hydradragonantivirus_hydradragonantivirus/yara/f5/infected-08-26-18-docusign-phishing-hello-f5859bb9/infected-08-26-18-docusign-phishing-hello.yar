rule infected_08_26_18_DocuSign_phishing_hello {
  meta:
    description = "phishing - file hello.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-26"
    hash1       = "dd7e28b3e1c7d175f023e4a0145a083776221d4a78fa5e1f6035a88ad826dfcb"

  strings:
    $s1  = "$headers = 'From: no_reply@mylinklog.com' . \"\\r\\n\";" fullword ascii
    $s2  = "$data .='Password='.\"\"; $data .=$_POST['password'].\"\\n\";" fullword ascii
    $s3  = "$error_messages[] = 'Please fill in your Password.';" fullword ascii
    $s4  = "User Agent: {$_SERVER['HTTP_USER_AGENT']}" fullword ascii
    $s5  = "Password: {$userdata['password']}" fullword ascii
    $s6  = "$to" fullword ascii
    $s7  = "define('FORM_SUBMITTED', (is_array($_POST) && 0 < count($_POST)) );" fullword ascii
    $s8  = "$error_messages[] = 'Please fill in your E-mail Address.';" fullword ascii
    $s9  = "$error_messages[] = 'Sorry, there was a problem sending your email, please try again.';" fullword ascii
    $s10 = "$value = trim($_POST[$key]);" fullword ascii
    $s11 = "foreach ( $userdata as $key => &$value ) {" fullword ascii
    $s12 = "if (!mail($to, $subject, $message, $headers) ) {" fullword ascii
    $s13 = "if ( isset($_POST[$key]) ) {" fullword ascii
    $s14 = "$data .='Email='.\"\"; $data .=$_POST['email'].\"\\n\";" fullword ascii
    $s15 = "// If no error messages have been set then everything must be okay" fullword ascii
    $s16 = "HTTP Referrer: {$userdata['http_referrer']}" fullword ascii
    $s17 = "// Attempt to send the email" fullword ascii
    $s18 = "// If data has been posted for this item:" fullword ascii
    $s19 = "$data .='IP='.\"\"; $data .=$_SERVER[\"REMOTE_ADDR\"].\"\\n\";" fullword ascii
    $s20 = "} elseif ( get_magic_quotes_gpc() ) {" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 9KB and
      (8 of them)
    ) or (all of them)
}