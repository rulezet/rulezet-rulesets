rule Trojan_Win32_AgentCrypt_SN_MTB{
	meta:
		description = "Trojan:Win32/AgentCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 1c 3b 8b 1b 81 e3 ff 00 00 00 29 c9 47 42 49 81 ff ?? ?? 00 00 75 05 bf 00 00 00 00 81 c2 ?? ?? ?? ?? c3 } 		$a_03_1 = {09 d2 31 1e 46 21 d2 39 c6 75 ?? c3 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}