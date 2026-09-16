rule Trojan_Win32_LummaStealer_Z_MTB_18{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 1c 38 88 1c 39 0f b6 5c 38 ff 88 5c 39 ff 0f b6 5c 38 fe 88 5c 39 fe 0f b6 5c 38 fd 88 5c 39 fd 0f b6 5c 38 fc 88 5c 39 fc 0f b6 5c 38 fb 88 5c 39 fb 0f b6 5c 38 fa 88 5c 39 fa 0f b6 5c 38 f9 88 5c 39 f9 83 c7 f8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}