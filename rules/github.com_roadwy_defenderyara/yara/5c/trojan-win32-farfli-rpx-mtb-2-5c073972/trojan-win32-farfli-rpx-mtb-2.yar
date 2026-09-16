rule Trojan_Win32_Farfli_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 33 81 ea 01 00 00 00 bf ?? ?? ?? ?? 43 29 ff 4f 39 c3 75 d5 01 d2 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}