rule PWS_Win32_Amadey_GG_MTB_3{
	meta:
		description = "PWS:Win32/Amadey.GG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 95 ec fe ff ff 8b 95 ec fe ff ff 0f b6 84 15 f8 fe ff ff 8b 8d f0 fe ff ff 0f b6 94 0d f8 fe ff ff 33 d0 89 95 d8 fd ff ff 8b 85 f0 fe ff ff 8a 8d d8 fd ff ff 88 8c 05 f8 fe ff ff 0f b6 95 d8 fd ff ff 8b 85 ec fe ff ff 0f b6 8c 05 f8 fe ff ff 33 ca 89 8d d4 fd ff ff 8b 95 ec fe ff ff 8a 85 d4 fd ff ff 88 84 15 f8 fe ff ff 0f b6 8d d4 fd ff ff 8b 95 f0 fe ff ff 0f b6 84 15 f8 fe ff ff 33 c1 8b 8d f0 fe ff ff 88 84 0d f8 fe ff ff e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}