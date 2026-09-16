rule Trojan_BAT_Jupyter_AJY_MTB{
	meta:
		description = "Trojan:BAT/Jupyter.AJY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 8e 69 1b 59 8d ?? ?? ?? 01 0b 16 0d 2b 0c 07 09 06 09 1b 58 91 9c 09 17 58 0d 09 07 8e 69 32 ee } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}