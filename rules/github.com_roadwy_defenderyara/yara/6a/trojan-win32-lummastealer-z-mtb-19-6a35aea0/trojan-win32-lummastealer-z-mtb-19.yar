rule Trojan_Win32_LummaStealer_Z_MTB_19{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 20 f3 45 88 d3 41 20 fb 41 30 fa 45 08 d3 41 88 ea 41 80 f2 ff 40 88 df 40 80 f7 ff 41 88 f6 41 80 f6 01 45 88 d7 41 80 e7 ff 44 20 f5 41 88 fc 41 80 e4 ff 44 20 f3 41 08 ef 41 08 dc 45 30 e7 41 08 fa 41 80 f2 ff 41 80 ce 01 45 20 f2 45 08 d7 45 88 da 41 80 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}