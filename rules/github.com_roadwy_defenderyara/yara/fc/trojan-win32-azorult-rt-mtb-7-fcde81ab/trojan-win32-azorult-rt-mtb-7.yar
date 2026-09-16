rule Trojan_Win32_Azorult_RT_MTB_7{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 fb 61 36 13 01 0f [0-05] eb ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 33 ff 81 ff cb 04 00 00 7d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}