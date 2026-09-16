rule Trojan_Win32_Glupteba_GD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c6 d3 e0 8b ce c1 e9 ?? 03 8d [0-10] 03 85 [0-10] 33 c1 8b 8d [0-10] 03 ce 33 c1 } 		$a_02_1 = {8b 45 7c 89 38 [0-10] 89 70 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}