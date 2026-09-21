rule sig_27138_Veeam_Get_Creds {
   meta:
      description = "27138 - file Veeam-Get-Creds.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/"
      date = "2025-01-23"
      hash1 = "18051333e658c4816ff3576a2e9d97fe2a1196ac0ea5ed9ba386c46defafdb88"
   strings:
      $x1 = "# Usage:  Run as administrator (elevated) in PowerShell on a host in a Veeam " fullword ascii
      $s2 = "$SqlDatabaseName = (Get-ItemProperty -Path $VeaamRegPath -ErrorAction Stop).SqlDatabaseName " fullword ascii
      $s3 = "$SqlServerName = (Get-ItemProperty -Path $VeaamRegPath -ErrorAction Stop).SqlServerName" fullword ascii
      $s4 = "$SqlInstanceName = (Get-ItemProperty -Path $VeaamRegPath -ErrorAction Stop).SqlInstanceName" fullword ascii
      $s5 = "$command = New-Object System.Data.OleDb.OleDbCommand $SQL, $connection" fullword ascii
      $s6 = "# About:  The script is designed to recover passwords used by Veeam to connect" fullword ascii
      $s7 = "$rows | ForEach-Object -Process {" fullword ascii
      $s8 = "$adapter = New-Object System.Data.OleDb.OleDbDataAdapter $command" fullword ascii
      $s9 = "\"Here are some passwords for you, have fun:\"" fullword ascii
      $s10 = "$SQL = \"SELECT [user_name] AS 'User name',[password] AS 'Password' FROM [$SqlDatabaseName].[dbo].[Credentials] \"+" fullword ascii
      $s11 = "$_.password = $enc.GetString($ClearPWD)" fullword ascii
      $s12 = "#         to remote hosts vSphere, Hyper-V, etc. The script is intended for " fullword ascii
      $s13 = "$EnryptedPWD = [Convert]::FromBase64String($_.password)" fullword ascii
      $s14 = "#Decrypting passwords using DPAPI" fullword ascii
      $s15 = "#Fetching encrypted credentials from the database" fullword ascii
      $s16 = "$connection = New-Object System.Data.OleDb.OleDbConnection $connectionString" fullword ascii
      $s17 = "\"No passwords today, sorry.\"" fullword ascii
      $s18 = "\"WHERE password <> ''\" #Filter empty passwords" fullword ascii
      $s19 = "# Author: Konstantin Burov." fullword ascii
      $s20 = "echo \"Can't find Veeam on localhost, try running as Administrator\"" fullword ascii
   condition:
      uint16(0) == 0x2023 and filesize < 7KB and
      1 of ($x*) and 4 of them
}