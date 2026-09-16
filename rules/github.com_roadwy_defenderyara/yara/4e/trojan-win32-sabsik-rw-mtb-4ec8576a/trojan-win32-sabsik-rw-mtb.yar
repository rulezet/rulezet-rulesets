rule Trojan_Win32_Sabsik_RW_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 f1 8b 64 45 2d 01 f2 89 44 24 ?? 89 54 24 ?? 8b 44 24 ?? 35 e4 ae 96 27 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}