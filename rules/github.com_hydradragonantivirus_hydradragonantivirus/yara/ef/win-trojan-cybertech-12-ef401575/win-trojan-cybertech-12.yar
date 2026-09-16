rule Win_Trojan_CyberTech_12
{
strings:
	$a0 = { 5d83ed07508dbe1b0089feb91304ac3400aae2fa }


condition:
	$a0
}