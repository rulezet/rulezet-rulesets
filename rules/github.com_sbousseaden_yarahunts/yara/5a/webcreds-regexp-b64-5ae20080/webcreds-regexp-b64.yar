rule webcreds_regexp_b64 {
meta:
 author = "SBousseaden"
 date = "03-08-2020"
 reference = "https://github.com/orlyjamie/mimikittenz/blob/master/Invoke-mimikittenz.ps1"
strings:
    $p1 = "&password=" base64
	$p2 = "&login_password=" base64
	$p3 = "&pass=" base64
	$p4 = "&Passwd=" base64
	$p5 = "&PersistentCookie=" base64
	$p6 = "password%5D=" base64
	$u1 = "&username=" base64
	$u2 = "&email=" base64
	$u3 = "login=" base64
	$u4 = "login_email=" base64
	$u5 = "user%5Bemail%5D=" base64
	$reg = ".{1,"
condition: 3 of ($p*) and 3 of ($u*) and #reg>3
}