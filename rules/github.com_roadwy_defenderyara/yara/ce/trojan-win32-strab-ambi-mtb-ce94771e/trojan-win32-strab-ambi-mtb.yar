rule Trojan_Win32_Strab_AMBI_MTB{
	meta:
		description = "Trojan:Win32/Strab.AMBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 c8 0f b6 4d ?? 31 c8 88 c1 8b 45 ?? 88 0c 05 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}