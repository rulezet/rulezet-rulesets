rule pdf1 
{
	meta: 
		author = "k3rnelcallz"
		description = "Phishing pdf drops malicious ZIP"	
		filename = "Tax Payment Notice.pdf"
		sha256 = "f9e832c9cd54668c35bab5077df30af51ced5f9473d570e73b369437a632523a"
        creation_date = "28-11-25"
		last_modified = "28-11-25"
		source = "Malwarebazaar"
		category = "Info"

	strings: 
		$magic = { 25 50 44 46 } 		$url = "http://" ascii nocase

	condition:
		$magic and
		$url 		
}