rule Win_Trojan_KrK_1
{
strings:
	$a0 = { fc025754561901bff934ca26ec0b272f642e274c754c203e31273a05cb7321ef59070918be27042cf12cf8fbf4a301 }


condition:
	$a0
}