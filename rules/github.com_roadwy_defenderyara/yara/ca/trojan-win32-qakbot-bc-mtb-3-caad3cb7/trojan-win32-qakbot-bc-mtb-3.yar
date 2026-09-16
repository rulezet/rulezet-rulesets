rule Trojan_Win32_QakBot_BC_MTB_3{
	meta:
		description = "Trojan:Win32/QakBot.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f af da 8b d3 c1 ea 08 88 14 01 ff 47 68 8b 4f 68 8b 87 b4 00 00 00 88 1c 01 8b 47 78 ff 47 68 35 40 77 20 00 29 47 6c 8b 87 c0 00 00 00 2b 47 6c 2d [0-04] 31 47 78 8b 47 74 2d [0-04] 01 47 64 8b 47 64 83 c0 ed 01 87 80 00 00 00 81 fd [0-04] 0f } 		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}