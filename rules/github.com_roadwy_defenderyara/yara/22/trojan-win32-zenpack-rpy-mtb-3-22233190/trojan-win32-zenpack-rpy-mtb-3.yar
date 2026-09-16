rule Trojan_Win32_Zenpack_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpack.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 85 ec fd ff ff 89 85 cc fc ff ff b8 1e 00 00 00 8d 8d ec fd ff ff 89 ca 81 c2 0a 00 00 00 89 ce 81 c6 06 00 00 00 89 cf 81 c7 10 00 00 00 89 cb 81 c3 0e 00 00 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}