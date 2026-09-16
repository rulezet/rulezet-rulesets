rule Trojan_Linux_ProcessHider_C_MTB{
	meta:
		description = "Trojan:Linux/ProcessHider.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {48 8b 15 90 29 00 00 48 8d 85 f0 fe ff ff 48 89 d6 48 89 c7 e8 7e fa ff ff 85 c0 75 05 e9 5d ff ff ff 90 48 8b 85 e8 fd ff ff 48 8b 4d f8 64 48 33 0c 25 28 00 00 00 } 		$a_00_1 = {48 8b 95 d8 fe ff ff 48 8d 85 e0 fe ff ff be 00 01 00 00 48 89 c7 e8 39 fd ff ff 48 85 c0 75 16 48 8b 85 d8 fe ff ff 48 89 c7 e8 d5 fc ff ff b8 00 00 00 00 eb 3d } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}