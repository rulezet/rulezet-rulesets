rule Win_Trojan_Vienna_57
{
strings:
	$a0 = { 0db440b988028bd681eaf901cd2172 }


condition:
	$a0
}