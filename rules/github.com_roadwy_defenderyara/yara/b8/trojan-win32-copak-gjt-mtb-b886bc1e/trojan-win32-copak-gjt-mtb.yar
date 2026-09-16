rule Trojan_Win32_Copak_GJT_MTB{
	meta:
		description = "Trojan:Win32/Copak.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 13 01 f8 21 ff 43 4f 81 c7 ?? ?? ?? ?? 81 c0 ?? ?? ?? ?? 39 f3 75 ?? 21 f8 c3 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}