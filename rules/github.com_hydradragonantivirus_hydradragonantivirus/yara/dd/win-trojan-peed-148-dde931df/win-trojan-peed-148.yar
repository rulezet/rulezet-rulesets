rule Win_Trojan_Peed_148
{
strings:
	$a0 = { e8ef00000083c40383c401bf00??4081bb87c7ebff01c789f89681c37238140083c30758b8b748a2 }


condition:
	$a0
}