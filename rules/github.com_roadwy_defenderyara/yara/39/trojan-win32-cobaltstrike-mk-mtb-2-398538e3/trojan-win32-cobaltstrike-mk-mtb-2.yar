rule Trojan_Win32_Cobaltstrike_MK_MTB_2{
	meta:
		description = "Trojan:Win32/Cobaltstrike.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c5 04 0f af 5f 30 8b 87 ?? ?? ?? ?? 8b d3 c1 ea 10 88 14 01 8b d3 ff 47 38 8b 8f ?? ?? ?? ?? 8b 47 3c 81 c1 ?? ?? ?? ?? 03 c1 c1 ea 08 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}