rule webshell_asp_shell : webshell {
	meta:
		description = "Web Shell - file shell.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "e63f5a96570e1faf4c7b8ca6df750237"
	strings:
		$s7 = "<input type=\"submit\" name=\"Send\" value=\"GO!\">" fullword
		$s8 = "<TEXTAREA NAME=\"1988\" ROWS=\"18\" COLS=\"78\"></TEXTAREA>" fullword
	condition:
		all of them
}