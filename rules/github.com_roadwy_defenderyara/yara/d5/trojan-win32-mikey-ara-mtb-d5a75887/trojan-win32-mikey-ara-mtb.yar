rule Trojan_Win32_Mikey_ARA_MTB{
	meta:
		description = "Trojan:Win32/Mikey.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8a 16 03 c1 30 10 41 3b 4d 0c 7c f1 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}