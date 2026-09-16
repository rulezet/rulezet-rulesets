rule Trojan_Win32_Glupteba_B_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {30 10 43 81 fb 10 00 00 00 75 0e 33 db eb 0a } 		$a_02_1 = {49 83 f9 ff 74 74 bb 28 00 00 00 0f af d9 51 a1 ?? ?? ?? ?? 83 c0 10 0f b7 10 03 da } 	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}