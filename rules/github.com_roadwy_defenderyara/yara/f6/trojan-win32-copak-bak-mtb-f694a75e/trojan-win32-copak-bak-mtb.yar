rule Trojan_Win32_Copak_BAK_MTB{
	meta:
		description = "Trojan:Win32/Copak.BAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 03 29 ff 09 f7 88 02 09 ff 42 89 ff 01 fe 09 ff 81 c3 02 00 00 00 89 f7 01 f6 39 cb 7e } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}