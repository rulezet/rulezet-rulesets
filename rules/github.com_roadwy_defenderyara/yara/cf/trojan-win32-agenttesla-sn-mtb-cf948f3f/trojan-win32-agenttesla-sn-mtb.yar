rule Trojan_Win32_AgentTesla_SN_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 3a 83 ea ?? f7 df 83 ef 2b 83 ef 02 83 c7 01 29 c7 89 f8 c7 46 00 00 00 00 00 31 3e 8d 5b fc 83 c6 04 85 db 75 ?? 83 c4 04 8b 74 24 fc [0-10] 68 ?? ?? ?? ?? ff e6 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}