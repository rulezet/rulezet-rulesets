rule Win_Trojan_Sova_1
{
strings:
	$a0 = { 0ebd57341ff8b9c60f9033f656f5fa5e4c4c5ef581c60002fc81fec30f7206f081eec30ff933 }


condition:
	$a0
}