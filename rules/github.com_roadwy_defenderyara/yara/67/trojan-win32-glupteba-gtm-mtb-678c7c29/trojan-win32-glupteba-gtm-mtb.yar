rule Trojan_Win32_Glupteba_GTM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 03 49 81 c7 ?? ?? ?? ?? 43 01 c9 39 d3 } 		$a_03_1 = {31 06 46 bf ?? ?? ?? ?? 47 39 ce ?? ?? c3 47 21 ff 8d 04 10 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}