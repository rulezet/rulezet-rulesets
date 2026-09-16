rule Trojan_Win32_LummaStealer_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 b0 6a 40 68 00 30 00 00 8b 4d e4 8b 51 50 52 6a 00 8b 45 cc 50 ff 55 b0 89 45 ec 83 7d ec 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}