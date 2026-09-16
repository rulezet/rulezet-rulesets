rule Trojan_Win32_LummaStealer_PI_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b0 40 c3 b0 3f c3 89 c8 04 d0 3c 09 77 06 80 c1 04 89 c8 c3 89 c8 04 bf 3c 1a 72 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}