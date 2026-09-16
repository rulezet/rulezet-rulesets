rule Win_Trojan_Leprosy_37
{
strings:
	$a0 = { cd21e80100c3bb31018a2732260601882743 }


condition:
	$a0
}