rule Trojan_Win32_Azorult_RTH_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 fe 93 8d 6a 8b 85 ?? ?? ?? ?? 8d 0c 16 33 c1 31 45 ?? 81 3d [0-05] a3 01 00 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}