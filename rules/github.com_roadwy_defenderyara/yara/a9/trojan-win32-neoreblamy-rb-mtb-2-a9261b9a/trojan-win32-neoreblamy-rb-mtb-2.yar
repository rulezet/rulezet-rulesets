rule Trojan_Win32_Neoreblamy_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Neoreblamy.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 7d 08 01 75 1c e8 ?? ?? ?? ?? 99 6a 03 59 f7 f9 42 42 69 c2 e8 03 00 00 50 ff 15 ?? ?? ?? ?? eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}