rule Trojan_Win32_Glupteba_NF_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 33 09 fa 09 ff 43 39 cb 75 90 0a 27 00 be ?? ?? ?? ?? 47 e8 ?? ?? ?? ?? 81 ef } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}