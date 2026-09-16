rule Trojan_Win32_AgentTesla_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/AgentTesla.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d3 83 c4 0c 68 96 00 00 00 ff d6 83 ef 01 75 e6 bf 1e 00 00 00 90 90 6a 00 6a 00 68 ?? ?? ?? ?? ff d3 83 c4 0c 68 9b 00 00 00 ff d6 83 ef 01 75 e6 bf 0f 00 00 00 90 90 6a 00 6a 00 68 ?? ?? ?? ?? ff d3 83 c4 0c 68 9b 00 00 00 ff d6 83 ef 01 75 e6 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}