rule Win_Trojan_Trust_1
{
strings:
	$a0 = { 402e8b1e1301b90100ba0401cd217203e951ffe91dff9c80fcff7504b4019dcf80fcfe7507f3a4 }


condition:
	$a0
}