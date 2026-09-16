rule Trojan_Win32_Glupteba_RPA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {21 db 29 df 31 16 47 81 eb ?? ?? ?? ?? 46 47 39 ce 75 df } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}