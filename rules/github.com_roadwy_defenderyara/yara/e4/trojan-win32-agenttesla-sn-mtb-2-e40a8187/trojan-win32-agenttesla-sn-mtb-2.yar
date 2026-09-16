rule Trojan_Win32_AgentTesla_SN_MTB_2{
	meta:
		description = "Trojan:Win32/AgentTesla.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {e8 af 00 00 00 [0-06] b9 ?? ?? ?? ?? [0-06] 81 c1 31 90 90 48 00 [0-06] 83 c6 ?? [0-06] 4e [0-06] 4e [0-06] ff 37 [0-06] 31 34 24 [0-06] 5b [0-06] 39 cb 75 e3 [0-06] bb 20 61 00 00 [0-06] 83 eb ?? [0-06] 83 eb ?? [0-06] ff 34 1f [0-10] 8f 04 18 [0-10] 31 34 18 [0-40] 83 fb 00 7f b5 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}