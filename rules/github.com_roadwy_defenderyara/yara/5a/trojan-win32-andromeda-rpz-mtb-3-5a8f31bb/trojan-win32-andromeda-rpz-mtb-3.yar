rule Trojan_Win32_Andromeda_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/Andromeda.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 45 14 56 57 8b 7d 08 33 f6 89 47 0c 39 75 10 76 15 8b 45 0c 57 8d 14 06 e8 ?? ?? ?? ?? 30 02 46 59 3b 75 10 72 eb 5f 5e 5d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}