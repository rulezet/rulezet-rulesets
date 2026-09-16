rule Trojan_Win32_Ursnif_SR_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a d0 81 ff d0 eb 6c 2d 75 90 0a 19 00 a0 ?? ?? ?? ?? 8b 75 00 2a c2 02 05 } 		$a_02_1 = {81 c6 ac 43 d5 01 0f b6 ca 81 c1 8a 1d 00 00 0f b7 c3 89 75 00 03 c1 8b 0d ?? ?? ?? ?? 83 c5 04 ff 4c 24 14 0f 85 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}