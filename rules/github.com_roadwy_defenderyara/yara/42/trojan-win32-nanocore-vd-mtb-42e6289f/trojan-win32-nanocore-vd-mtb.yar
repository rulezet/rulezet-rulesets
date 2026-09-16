rule Trojan_Win32_NanoCore_VD_MTB{
	meta:
		description = "Trojan:Win32/NanoCore.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 34 01 17 41 81 f9 ?? ?? ?? ?? 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}