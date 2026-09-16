rule Trojan_Win32_NanoCore_VD_MTB_3{
	meta:
		description = "Trojan:Win32/NanoCore.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 45 fc 41 39 d1 75 90 09 0b 00 c7 45 fc ?? ?? ?? ?? 80 34 01 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}