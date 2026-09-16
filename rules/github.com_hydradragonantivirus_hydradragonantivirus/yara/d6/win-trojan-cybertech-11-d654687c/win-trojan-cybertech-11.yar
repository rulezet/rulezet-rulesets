rule Win_Trojan_CyberTech_11
{
strings:
	$a0 = { 5d83ed07508dbe1b0089feb9b504ac3400aae2fa }


condition:
	$a0
}