rule Trojan_Win32_UrSnif_RPX_MTB{
	meta:
		description = "Trojan:Win32/UrSnif.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 8b 8d 68 fe ff ff 03 ce 2b c8 46 88 19 3b b5 6c fe ff ff 72 c9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}