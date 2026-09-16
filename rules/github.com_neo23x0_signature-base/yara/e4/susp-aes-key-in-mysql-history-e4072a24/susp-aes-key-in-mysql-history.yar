rule SUSP_AES_Key_in_MySql_History {
	meta:
		description = "Detects AES key outside of key management in .mysql_history"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp"
		date = "2022-11-22"
		score = 50
		id = "28acef39-8606-5d3d-b395-0d8db13f6c9c"
	strings:
		$c1 = /\bAES_(DE|EN)CRYPT\(.{1,128}?,.??('|").{1,128}?('|")\)/ ascii
		$c2 = /\baes_(de|en)crypt\(.{1,128}?,.??('|").{1,128}?('|")\)/ ascii

	condition:
		filename == ".mysql_history" and 
		any of ($c*)
}