rule mailer_5d9374665f5da {
  meta:
    description = "PHP - file mailer_5d9374665f5da.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-10-11"
    hash1       = "5a3ac415ae87f2a4984f2721f1ba75b65c3dcdf5a1b123d431545a3d6501dd6d"

  strings:
    $s1  = "$headers.='From: '.'=?utf-8?B?'.base64_encode(randText()).'?='.' <'.$from_name.'@'.$_SERVER['HTTP_HOST'].'>'.\"\\r\\n\";" fullword ascii
    $s2  = "$header='From: '.'=?utf-8?B?'.base64_encode(randText()).'?='.' <'.$from_name.'@'.$_SERVER['HTTP_HOST'].\">\\r\\n\";" fullword ascii
    $s3  = "$headers.='From: =?utf-8?B?'.base64_encode($from).'?= <'.$from_name.'@'.$_SERVER['HTTP_HOST'].'>'.\"\\r\\n\";" fullword ascii
    $s4  = "$header='From: =?utf-8?B?'.base64_encode($from).'?= <'.$from_name.'@'.$_SERVER['HTTP_HOST'].\">\\r\\n\";" fullword ascii
    $s5  = "$headers.='Content-Type: multipart/mixed; boundary=\"'.$boundary.\"\\\"\\r\\n\\r\\n\";" fullword ascii
    $s6  = "$ip=gethostbyname($_SERVER['HTTP_HOST']); $result='';" fullword ascii
    $s7  = "return file_get_contents($_FILES['file']['tmp_name']);" fullword ascii
    $s8  = "$header.='Content-Type: text/html; charset=\"utf-8\"'.\"\\r\\n\";" fullword ascii
    $s9  = "$header.='Content-Type: '.$type.'; charset=\"utf-8\"'.\"\\r\\n\";" fullword ascii
    $s10 = "$login=strtolower(str_replace('.','',$login[0]));" fullword ascii
    $s11 = "$dnsbl_check=array('b.barracudacentral.org','xbl.spamhaus.org','sbl.spamhaus.org','zen.spamhaus.org','bl.spamcop.net');" fullword ascii
    $s12 = "$login=explode('@',$email); $result='';" fullword ascii
    $s13 = "$body.='Content-Disposition: attachment; filename=\"'.$filename.'\"'.\"\\r\\n\";" fullword ascii
    $s14 = "$body.='Content-Type: '.$_FILES['file']['type'].'; name=\"'.$filename.'\"'.\"\\r\\n\";" fullword ascii
    $s15 = "$r_from=Random(dataHandler(urldecode($_POST['f'])),$data);" fullword ascii
    $s16 = "$headers.='X-Mailer: PHP/'.phpversion().\"\\r\\n\";" fullword ascii
    $s17 = "return $result.'@gmail.com';" fullword ascii
    $s18 = "$replyto=$from_name.'@'.$_SERVER['HTTP_HOST'];" fullword ascii
    $s19 = "$reply=$from_name.'@'.$_SERVER['HTTP_HOST'];" fullword ascii
    $s20 = "$filename=filename('1.txt'); $boundary=md5(uniqid());" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 40KB and
      (8 of them)
    ) or (all of them)
}