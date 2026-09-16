rule Win_Trojan_Gbot_5
{
strings:
	$a0 = { 558bec81eca40100006a006a006a00fc26ff15????410083e8??8b110fafc2263c7c36??2d8d44240450546a01ff15????41003b042a745e26b8????4000 }


condition:
	$a0
}