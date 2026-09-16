rule webshell_cihshell_fix : webshell {
	meta:
		description = "Web Shell - file cihshell_fix.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "3823ac218032549b86ee7c26f10c4cb5"
	strings:
		$s7 = "<tr style='background:#242424;' ><td style='padding:10px;'><form action='' encty"
		$s8 = "if (isset($_POST['mysqlw_host'])){$dbhost = $_POST['mysqlw_host'];} else {$dbhos"
	condition:
		1 of them
}