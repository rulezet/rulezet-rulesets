rule Trojan_Win64_Bumblebee_GTB_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.GTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c8 8b c1 89 84 24 ?? ?? ?? ?? 0f be 44 24 ?? 83 f0 7d 88 44 24 ?? 0f b6 44 24 } 		$a_01_1 = {64 65 61 64 6c 69 6c 79 20 41 73 65 6c 6c 69 6e 65 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}