rule Trojan_Win32_LummaStealer_PGLN_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PGLN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 75 ?? c0 e1 ?? 32 cb c0 e1 ?? 8a 04 3a c0 e8 ?? 32 c8 8b 45 ?? 88 0c 03 43 81 fb ?? ?? ?? ?? 72 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}