rule Trojan_Win32_Rotaderp_B_2{
	meta:
		description = "Trojan:Win32/Rotaderp.B,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2f 63 20 69 66 20 6e 6f 74 20 25 63 6f 6d 70 75 74 65 72 6e 61 6d 65 25 20 3d 3d 20 44 45 53 4b 54 4f 50 2d 51 4f 35 51 55 33 33 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}