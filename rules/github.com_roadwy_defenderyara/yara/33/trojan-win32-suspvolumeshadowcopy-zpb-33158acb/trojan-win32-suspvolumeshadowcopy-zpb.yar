rule Trojan_Win32_SuspVolumeShadowCopy_ZPB{
	meta:
		description = "Trojan:Win32/SuspVolumeShadowCopy.ZPB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {64 00 69 00 73 00 6b 00 73 00 68 00 61 00 64 00 6f 00 77 00 90 00 02 00 0a 00 20 00 2f 00 73 00 } 	condition:
		((#a_00_0  & 1)*1) >=1
 
}