rule Trojan_Win64_Emotet_BK_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0c 01 42 32 4c 16 fd 41 88 4a ff 49 ff ce 0f 85 48 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}