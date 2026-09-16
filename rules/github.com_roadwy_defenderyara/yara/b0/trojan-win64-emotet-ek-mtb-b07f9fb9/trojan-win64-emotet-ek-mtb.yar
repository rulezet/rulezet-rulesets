rule Trojan_Win64_Emotet_EK_MTB{
	meta:
		description = "Trojan:Win64/Emotet.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 b9 27 00 00 00 f7 f9 48 63 ca 48 8b 05 ?? ?? ?? ?? 0f b6 04 08 41 8b d0 33 d0 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}