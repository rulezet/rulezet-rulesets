rule Trojan_Win32_Azorult_RT_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 03 45 ?? 8d 4d [0-05] c7 05 ?? ?? ?? ?? b4 02 d7 cb c7 05 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}