rule Trojan_Win32_Vidar_SPDB_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SPDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 c0 fd 43 03 00 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 30 0c 33 83 ff 0f } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}