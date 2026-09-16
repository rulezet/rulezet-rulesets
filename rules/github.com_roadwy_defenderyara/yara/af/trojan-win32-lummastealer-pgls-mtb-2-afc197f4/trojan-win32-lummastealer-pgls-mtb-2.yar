rule Trojan_Win32_LummaStealer_PGLS_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.PGLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 34 ?? 56 50 e8 ?? ?? ?? ?? 83 c4 ?? 88 44 34 ?? 46 83 fe ?? 75 } 		$a_03_1 = {0f b6 44 1c ?? 53 50 e8 ?? ?? ?? ?? 83 c4 ?? 88 44 1c ?? 43 83 fb ?? 75 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}