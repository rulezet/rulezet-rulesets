rule Trojan_Win32_Glupteba_GZZ_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 0f 81 c7 04 00 00 00 39 f7 ?? ?? 81 c0 ?? ?? ?? ?? 81 c3 } 		$a_01_1 = {31 17 81 c7 04 00 00 00 09 d9 39 c7 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10) >=10
 
}