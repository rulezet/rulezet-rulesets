rule Win_Trojan_Xdoor_1
{
strings:
	$a0 = { 8b8d48ffffff8b55908b45885152508d4d80685830011051c645fc17e8167b00008b8588fdffff83c41433f689854cffffff85c07e48 }


condition:
	$a0
}