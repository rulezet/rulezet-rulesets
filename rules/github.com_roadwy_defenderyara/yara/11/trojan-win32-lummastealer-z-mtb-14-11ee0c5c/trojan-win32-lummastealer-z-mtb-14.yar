rule Trojan_Win32_LummaStealer_Z_MTB_14{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7a 36 14 1b 4f b1 6b 6b 91 3c f8 0c ed 40 a6 38 f9 ef 8b 67 d6 8c b2 1b af 31 c5 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}