rule Win_Trojan_Mac_1
{
strings:
	$a0 = { b9480c33d2e8130772213bc1751db800428b163b018b0e3d01e8ff06b44033c9e8f806 }


condition:
	$a0
}