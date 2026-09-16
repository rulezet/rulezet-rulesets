rule Win_Trojan_Sirius_44
{
strings:
	$a0 = { e80000582d0801958db62201568b961202b978008bfead33c2abe2fac3 }


condition:
	$a0
}