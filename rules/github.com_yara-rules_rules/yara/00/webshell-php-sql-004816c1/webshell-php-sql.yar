rule webshell_PHP_sql  : webshell {
	meta:
		description = "Web Shell - file sql.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "2cf20a207695bbc2311a998d1d795c35"
	strings:
		$s0 = "$result=mysql_list_tables($db) or die (\"$h_error<b>\".mysql_error().\"</b>$f_"
		$s4 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&"
	condition:
		all of them
}