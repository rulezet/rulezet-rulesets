rule Trojan_Win32_Scarsi_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/Scarsi.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f0 83 c1 01 89 4d f0 8b 55 f0 3b 15 84 50 40 00 73 33 83 7d f0 00 7c 2b 8b 45 f0 99 b9 0a 00 00 00 f7 f9 8b 45 fc 0f be 0c 10 8b 15 6c 50 40 00 03 55 f0 0f be 02 33 c1 8b 0d 6c 50 40 00 03 4d f0 88 01 eb b9 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}