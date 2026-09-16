rule TimeStomp {
 	meta:
        	mitre = "T1070 Indicator Removal on Host: Timestomp, T1036 Masquerading"
 	strings:
       		$a = "touch" fullword
		$A = "touch" base64
   	condition:
 		any of them
}