rule Win_Trojan_Nostardamus_10
{
strings:
	$a0 = { a851c30252bea4136baa6bbd4112acc20fe4a8650ef5c25e75d829a1baaeaa6dc9e1eff6573cac8e8346e013 }


condition:
	$a0
}