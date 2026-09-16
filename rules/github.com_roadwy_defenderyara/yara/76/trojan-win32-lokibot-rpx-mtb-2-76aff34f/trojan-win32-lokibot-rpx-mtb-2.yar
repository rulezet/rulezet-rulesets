rule Trojan_Win32_LokiBot_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 65 c4 00 83 7d c4 01 73 06 83 65 a8 00 eb 08 e8 ?? ?? ?? ?? 89 45 a8 ba ?? ?? ?? ?? 8b 45 c4 8b 4d e4 8d 0c 81 e8 ?? ?? ?? ?? ff 75 c0 ff 75 bc ff 75 b8 ff 75 b4 8d 45 cc 50 e8 ?? ?? ?? ?? 89 45 ac 83 7d ac 00 75 b7 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}