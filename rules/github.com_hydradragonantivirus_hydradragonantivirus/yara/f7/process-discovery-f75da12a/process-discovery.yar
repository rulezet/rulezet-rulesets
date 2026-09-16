rule Process_Discovery {
 	meta:
		mitre = "T1057 Process Discovery"
 	strings:
       		$a = "ps ax"
		$b = "ps -p -o"
		$c = "ps -eAo"
		$d = "ps -ef"
		$e = "ps aux"
       		$A = "ps ax" base64
		$B = "ps -p -o" base64
		$C = "ps -eAo" base64
		$D = "ps -ef" base64
		$E = "ps aux" base64

   	condition:
		any of them
}