rule Trojan_Win32_TrickBot_GB_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 8a [0-03] 03 e8 89 44 [0-02] 81 e5 ff 00 00 00 8a 5c [0-02] 88 5c [0-02] 88 44 [0-02] ff 15 [0-04] 8a 4c [0-02] 8b 84 [0-05] 02 d9 8a [0-02] 81 ?? ff 00 00 00 8a [0-03] 32 ?? 88 [0-02] 8b [0-06] 46 3b [0-09] 81 c4 [0-04] c3 90 0a 8d 00 47 33 [0-03] ff 00 00 00 33 } 		$a_80_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } 	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}