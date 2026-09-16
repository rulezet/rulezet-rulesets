rule Trojan_Win64_Emotet_BK_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0c 01 32 4c 3e ff 49 ff cd 88 4f ff 75 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}