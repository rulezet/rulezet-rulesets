rule Ransom_Win32_Locky_RPX_MTB{
	meta:
		description = "Ransom:Win32/Locky.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d9 8b 4d ec 03 c2 8a 0c 01 32 cb 42 88 08 3b d6 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}