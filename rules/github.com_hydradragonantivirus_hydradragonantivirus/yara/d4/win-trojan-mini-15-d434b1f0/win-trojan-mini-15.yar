rule Win_Trojan_Mini_15
{
strings:
	$a0 = { eef08ec26056b5ff8bfe83c66ff3a4a4fe44fdb426cd21ba68272af4b44ecd217235b8ff3c40 }


condition:
	$a0
}