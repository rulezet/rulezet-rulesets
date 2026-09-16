rule Trojan_Win32_LummaStealer_RPG_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 72 62 00 73 69 68 78 75 69 41 73 75 69 61 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}