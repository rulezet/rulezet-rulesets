rule is_PDF 
{
	meta: 
		author = "k3rnelcallz"
		description = "Rule identifying PDF files"
		sha256 = "f9e832c9cd54668c35bab5077df30af51ced5f9473d570e73b369437a632523a"		
		creation_date = "28-11-25"
		last_modified = "03-12-25"
		source = "Malwarebazaar"
		category = "Info"

	strings:
		$pdf = {25 50 44 46 2D} 
	condition:
		$pdf at 0
}