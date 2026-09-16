rule Trojan_Win32_Convagent_BD_MTB{
	meta:
		description = "Trojan:Win32/Convagent.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {97 08 18 78 64 81 50 07 e8 eb 46 86 d9 01 92 86 1b 31 ac d0 40 a1 0f 90 d0 97 88 1e e0 80 c1 02 2e ac e1 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}