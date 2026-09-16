rule Spammer_Win32_Tedroo_F{
	meta:
		description = "Spammer:Win32/Tedroo.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8c b5 b8 34 24 40 cd 9e 31 53 1c b4 f3 43 5a e6 fe 4c 4f 47 47 45 52 08 0b 4f 42 0b 73 c9 6b 64 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}