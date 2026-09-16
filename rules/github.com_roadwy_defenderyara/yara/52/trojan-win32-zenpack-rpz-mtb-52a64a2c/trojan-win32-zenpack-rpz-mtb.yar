rule Trojan_Win32_Zenpack_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 48 42 39 4e 37 36 32 43 33 83 c4 04 eb 03 50 47 4e 59 8b 0f ff 77 08 8b 45 00 03 cb 51 8b cd ff 10 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}