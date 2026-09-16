rule Trojan_Win32_AgentTesla_RPX_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 e1 c1 ea 03 8d 14 52 03 d2 03 d2 8b c1 2b c2 8a 90 f8 91 40 00 30 14 31 41 3b cf 72 dd } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}