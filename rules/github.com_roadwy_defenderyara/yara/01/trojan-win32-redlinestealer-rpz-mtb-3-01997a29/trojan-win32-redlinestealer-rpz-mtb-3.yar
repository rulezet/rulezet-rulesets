rule Trojan_Win32_RedLineStealer_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {eb 02 f6 bf 50 eb 02 8d 43 e8 1a 00 00 00 eb 04 be da 68 17 eb } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}