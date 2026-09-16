rule Win_Trojan_Italian_5
{
strings:
	$a0 = { 96880259cd217210b002e82900b440b959018d960501cd21b801572e8b8e74022e8b9676 }


condition:
	$a0
}