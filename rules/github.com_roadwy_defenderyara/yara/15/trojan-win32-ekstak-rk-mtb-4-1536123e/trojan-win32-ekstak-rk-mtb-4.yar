rule Trojan_Win32_Ekstak_RK_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {df 6c 24 04 dc 05 58 d0 65 00 dd 1d 58 d0 65 00 ff 15 b0 b2 65 00 a1 04 05 66 00 50 ff 15 0c b2 65 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}