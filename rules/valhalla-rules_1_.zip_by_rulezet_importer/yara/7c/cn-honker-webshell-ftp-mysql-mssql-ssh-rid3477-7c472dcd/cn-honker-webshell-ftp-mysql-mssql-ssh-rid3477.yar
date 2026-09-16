rule CN_Honker_Webshell_FTP_MYSQL_MSSQL_SSH_RID3477 : CHINA DEMO T1021_004 T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file FTP MYSQL MSSQL SSH.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:31:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1021_004, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$_SESSION['hostlist'] = $hostlist = $_POST['hostlist'];" fullword ascii
      $s2 = "Codz by <a href=\"http://www.sablog.net/blog\">4ngel</a><br />" fullword ascii
      $s3 = "if ($conn_id = @ftp_connect($host, $ftpport)) {" fullword ascii
      $s4 = "$_SESSION['sshport'] = $mssqlport = $_POST['sshport'];" fullword ascii
      $s5 = "<title>ScanPass(FTP/MYSQL/MSSQL/SSH) by 4ngel</title>" fullword ascii
   condition: 
      filesize < 20KB and 3 of them
}