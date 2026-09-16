rule Trojan_Win32_Ursnif_AG_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 ce 83 e6 03 75 [0-20] 66 01 da 6b d2 ?? c1 ca 05 [0-20] 30 10 40 e2 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}