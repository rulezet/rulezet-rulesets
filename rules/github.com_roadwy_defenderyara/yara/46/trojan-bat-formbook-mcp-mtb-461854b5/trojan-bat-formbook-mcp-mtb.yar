rule Trojan_BAT_FormBook_MCP_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 58 56 4d 2e 30 48 61 72 6d 6f 6e 79 2e 62 69 6e } 		$a_01_1 = {53 58 56 4d 2e 70 61 79 6c 6f 61 64 2e 62 69 6e } 		$a_01_2 = {31 64 35 65 34 66 38 61 39 63 32 62 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}