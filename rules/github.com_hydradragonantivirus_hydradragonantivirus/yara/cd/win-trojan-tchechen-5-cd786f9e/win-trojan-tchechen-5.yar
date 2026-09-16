rule Win_Trojan_Tchechen_5
{
strings:
	$a0 = { cd1a720780fa107502eb05ea007c0000b280bebe07b7808a74018b4c02bf0a00b81102cd13fe }


condition:
	$a0
}