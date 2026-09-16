rule Win_Trojan_BewareBug_3
{
strings:
	$a0 = { 54bb7544b96c61cd2181fb7447750981f9214d7503e936058cc1b8203540cd218cc25107891e2e }


condition:
	$a0
}