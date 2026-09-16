rule Win_Trojan_Vienna_18
{
strings:
	$a0 = { f983c70205030103c18905b4408bfa2bd1b96901cd }


condition:
	$a0
}