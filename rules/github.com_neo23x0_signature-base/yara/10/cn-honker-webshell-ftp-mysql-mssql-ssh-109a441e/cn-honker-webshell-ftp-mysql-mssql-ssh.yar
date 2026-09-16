rule CN_Honker_Webshell_FTP_MYSQL_MSSQL_SSH {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file FTP MYSQL MSSQL SSH.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "fe63b215473584564ef2e08651c77f764999e8ac"
		id = "dd619901-6f0e-527e-9926-808176641c09"
	strings:
		$s1 = "$_SESSION['hostlist'] = $hostlist = $_POST['hostlist'];" fullword ascii 
		$s2 = "Codz by <a href=\"http://www.sablog.net/blog\">4ngel</a><br />" fullword ascii
		$s3 = "if ($conn_id = @ftp_connect($host, $ftpport)) {" fullword ascii 
		$s4 = "$_SESSION['sshport'] = $mssqlport = $_POST['sshport'];" fullword ascii 
		$s5 = "<title>ScanPass(FTP/MYSQL/MSSQL/SSH) by 4ngel</title>" fullword ascii 
	condition:
		filesize < 20KB and 3 of them
}