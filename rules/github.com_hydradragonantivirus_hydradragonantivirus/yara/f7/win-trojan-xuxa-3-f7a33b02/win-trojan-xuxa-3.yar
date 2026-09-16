rule Win_Trojan_Xuxa_3
{
strings:
	$a0 = { b644018dbe4401b9fc032e8a9613018a0432c2eb04b44ccd21c0c00526880546474975e6eb00 }


condition:
	$a0
}