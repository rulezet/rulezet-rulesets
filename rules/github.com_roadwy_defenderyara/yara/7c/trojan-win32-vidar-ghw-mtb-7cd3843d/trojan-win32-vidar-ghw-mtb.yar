rule Trojan_Win32_Vidar_GHW_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {6b e9 5c 3d 0f be 45 99 0f be 4d 9a 2b c1 88 45 99 0f be 45 e7 99 35 ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 66 a3 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}