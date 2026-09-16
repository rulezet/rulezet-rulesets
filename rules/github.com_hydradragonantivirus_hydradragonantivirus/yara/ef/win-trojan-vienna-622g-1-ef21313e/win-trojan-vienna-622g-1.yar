rule Win_Trojan_Vienna_622G_1
{
strings:
	$a0 = { bf0001b90300f3a48bf2b430cd213c007503e9a701 }


condition:
	$a0
}