rule Trojan_Win32_LummaStealer_FAJ_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.FAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 0f 32 4d ff 8b 5d 14 8b 45 ?? 88 0f 8b 4d 08 3b 55 0c 72 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}