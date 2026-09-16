rule Trojan_Win32_LummaStealer_PGLS_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PGLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c7 f7 75 ?? 8b 45 ?? 8a 04 02 32 c1 8b 4d ?? 32 01 8b 4d ?? 88 04 31 46 81 fb ?? ?? ?? ?? 0f 82 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}