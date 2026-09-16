rule marcher1
{
	meta:
		author = "Antonio S. <asanchez@koodous.com>"
		source = "https://analyst.koodous.com/rulesets/890"
		description = "This rule detects is to detect a type of banking malware"
		sample = "33b1a9e4a1591c1a39fdd5295874e365dbde9448098254a938525385498da070"

	strings:
		$a = "cmVudCYmJg=="
		$b = "dXNzZCYmJg=="

	condition:
		all of them
		
}