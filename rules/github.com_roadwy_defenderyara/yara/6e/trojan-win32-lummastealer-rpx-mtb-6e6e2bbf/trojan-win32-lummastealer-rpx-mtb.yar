rule Trojan_Win32_LummaStealer_RPX_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 d3 56 56 80 ea 13 46 d0 ca 46 f6 d2 f7 d6 fe c2 56 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}