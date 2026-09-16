rule powershell_dropper { 

	meta: 
		author = "k3rnelcallz"
		description = "powershell dropper with hidden bypass execution and persistence"
		sha256 = "f9e832c9cd54668c35bab5077df30af51ced5f9473d570e73b369437a632523a"
        creation_date = "1-12-25"
		last_modified = "2-12-25"
		source = "Malwarebazaar"
		category = "Info"

	strings:
		
		$e1 = "-ExecutionPolicy bypass" nocase
		$e2 = "-windowstyle hidden" nocase
		$e3 = "System.Net.WebClient" nocase
		$e4 = "DownloadFile" nocase

 		
 		$bat = ".bat"
 		$run = "\\CurrentVersion\\Run"

 	condition:
 		uint16(0) != 0x5A4D 
 		and
 		(
 		(3 of ($e*))
 		or
 		($bat and $run)
 		)
}