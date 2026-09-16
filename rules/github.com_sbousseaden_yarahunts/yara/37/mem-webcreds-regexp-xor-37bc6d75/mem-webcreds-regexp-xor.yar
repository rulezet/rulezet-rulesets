rule mem_webcreds_regexp_xor {
meta:
 author = "SBousseaden"
 date = "03-08-2020"
 reference = "https://github.com/orlyjamie/mimikittenz/blob/master/Invoke-mimikittenz.ps1"
strings:
    $p1 = "&password=" xor
	$p2 = "&login_password=" xor
	$p3 = "&pass=" xor
	$p4 = "&Passwd=" xor
	$p5 = "&PersistentCookie=" xor
	$p6 = "password%5D=" xor
	$u1 = "&username=" xor
	$u2 = "&email=" xor
	$u3 = "login=" xor
	$u4 = "login_email=" xor
	$u5 = "user%5Bemail%5D=" xor
	$reg = ".{1," xor
condition: 3 of ($p*) and 3 of ($u*) and #reg>3
}