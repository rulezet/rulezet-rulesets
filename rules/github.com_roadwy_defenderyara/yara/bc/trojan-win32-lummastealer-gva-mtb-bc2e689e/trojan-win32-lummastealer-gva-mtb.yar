rule Trojan_Win32_LummaStealer_GVA_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f 9c c0 0f 9c 44 24 ?? 30 c3 89 da f6 d2 20 c2 89 d0 30 d8 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}