rule Trojan_Win32_LummaStealer_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 46 78 89 c4 50 83 ec 1c 89 e0 83 e0 f0 89 46 70 89 c4 50 83 ec 0c 89 e0 83 e0 f0 89 46 7c 89 c4 50 83 ec 1c 89 e0 83 e0 f0 89 86 80 00 00 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}