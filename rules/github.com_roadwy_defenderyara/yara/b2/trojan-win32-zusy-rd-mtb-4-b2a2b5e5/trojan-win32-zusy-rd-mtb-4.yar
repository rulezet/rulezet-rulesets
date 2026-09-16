rule Trojan_Win32_Zusy_RD_MTB_4{
	meta:
		description = "Trojan:Win32/Zusy.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 e8 0f b6 44 2c 30 88 44 1c 30 88 4c 2c 30 0f b6 44 1c 30 03 c2 0f b6 c0 0f b6 44 04 30 32 87 ?? ?? ?? ?? 88 44 3c 1c 47 83 ff 14 72 c1 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}