rule Trojan_Win32_Azorult_RT_MTB_13{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 fd 9d 06 00 00 74 ?? 45 81 fd 61 36 13 01 0f [0-05] eb [0-05] a1 [0-05] a3 [0-05] 33 ff } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}