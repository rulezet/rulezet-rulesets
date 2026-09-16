rule Trojan_Win32_Injector_RPW_MTB_2{
	meta:
		description = "Trojan:Win32/Injector.RPW!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3d c4 00 00 00 83 fb 1a 31 db 83 f8 00 83 fa 0d 33 1c 0e 83 fa 57 83 fb 5d 09 1c 08 81 fb a3 00 00 00 81 f9 fa 00 00 00 31 3c 08 83 f8 11 81 fb 9b 00 00 00 81 e9 42 02 00 00 83 f9 21 83 f9 1b 81 c1 3d 02 00 00 90 83 f9 1a 41 7d b3 83 f8 02 81 fa d5 00 00 00 ff e0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}