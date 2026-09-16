rule Trojan_Win32_Redline_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 bf 3c b6 22 f7 e2 c1 ea 03 0f be c2 8b 54 24 14 8a ca 6b c0 3b 2a c8 80 c1 33 30 4c 14 1c 42 89 54 24 14 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}