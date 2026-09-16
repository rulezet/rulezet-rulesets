rule Win_Trojan_Gip_2
{
strings:
	$a0 = { 4769745005446f576e4c0e86641488e52f80701c4745541b62b47730e250 }


condition:
	$a0
}