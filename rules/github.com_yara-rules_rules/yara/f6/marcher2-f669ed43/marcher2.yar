rule marcher2
{
	meta:
		author = "Antonio S. <asanchez@koodous.com>"
		source = "https://analyst.koodous.com/rulesets/890"
	strings:
		$a = "HDNRQ2gOlm"
		$b = "lElvyohc9Y1X+nzVUEjW8W3SbUA"
	condition:
		all of them
		
}