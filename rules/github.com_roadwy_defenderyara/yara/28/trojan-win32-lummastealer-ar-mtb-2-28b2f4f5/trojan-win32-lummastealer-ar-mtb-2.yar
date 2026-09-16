rule Trojan_Win32_LummaStealer_AR_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 54 24 02 0f b6 4c 24 03 89 d3 88 cf 88 ce 80 f3 01 80 f7 01 88 dd 08 fe 20 cf 30 d5 80 f7 01 88 f0 20 dd 08 d3 } 		$a_01_1 = {89 d0 30 ca 08 c8 80 f2 01 89 c1 30 d1 08 c2 88 f0 34 01 80 f2 01 88 c4 08 ca 88 f1 20 f4 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}