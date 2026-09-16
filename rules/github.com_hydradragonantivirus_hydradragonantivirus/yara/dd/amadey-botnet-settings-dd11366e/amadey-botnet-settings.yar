rule amadey_botnet_settings {
  meta:
    description = "amadey-botnet - file settings.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-01-30"
    hash1       = "25e3e53e418fa237a6620570acd55bf888c183623ae0991e89f773822c0fd862"

  strings:
    $x1  = "SaveConfig( $_POST[\"newlogin\"], $_POST[\"newpass\"], $_POST[\"oldpass\"], $_POST[\"obslogin\"], $_POST[\"obspass\"] );" fullword ascii
    $s2  = "$content = $content . $cr . $pr . \"\\$conf[\\\"observer_login\\\"]\" . $rn . \"\\\"\" . $ologin . \"\\\";\";" fullword ascii
    $s3  = "$content = $content . $cr . $pr . \"\\$conf[\\\"observer_login\\\"]\" . $rn . \"\\\"\" . $obslogin . \"\\\";\";" fullword ascii
    $s4  = "$content = $content . $cr . $pr . \"\\$conf[\\\"login\\\"]\" . $rn . \"\\\"\" . $clogin . \"\\\";\";" fullword ascii
    $s5  = "$content = $content . $cr . $pr . \"\\$conf[\\\"observer_password\\\"]\" . $rn . \"\\\"\" . md5( $obspass ) . \"\\\";\";" fullword ascii
    $s6  = "$content = $content . $cr . $pr . \"\\$conf[\\\"login\\\"]\" . $rn . \"\\\"\" . $newlogin . \"\\\";\";" fullword ascii
    $s7  = "SaveSQL( $_POST[\"sqlhost\"], $_POST[\"sqlname\"], $_POST[\"sqluser\"], $_POST[\"sqlpass\"], $_POST[\"oldpass\"] ); " fullword ascii
    $s8  = "$content = $content . $cr . $pr . \"\\$conf[\\\"password\\\"]\" . $rn . \"\\\"\" . md5( $newpass ) . \"\\\";\";" fullword ascii
    $s9  = "`unitid` varchar(16) NOT NULL, `exec` tinyint(1) NOT NULL DEFAULT '0', PRIMARY KEY (`id`), KEY `unitid` (`unitid`) ) ENGINE=MyI" fullword ascii
    $s10 = "$content = $content . $cr . $pr . \"\\$conf[\\\"observer_password\\\"]\" . $rn . \"\\\"\" . $opass . \"\\\";\";" fullword ascii
    $s11 = "$content = $content . $cr . $pr . \"\\$conf[\\\"password\\\"]\" . $rn . \"\\\"\" . $cpass . \"\\\";\";" fullword ascii
    $s12 = "function SaveConfig( $newlogin, $newpass, $oldpass, $obslogin, $obspass )" fullword ascii
    $s13 = "* Please enter observer login name." fullword ascii
    $s14 = "mysql_query( \"CREATE TABLE IF NOT EXISTS `tasks_exec` ( `id` int(11) NOT NULL AUTO_INCREMENT, `task_id` int(11) NOT NULL," fullword ascii
    $s15 = "&nbsp;<img src=\\\"images\\ic_2.png\\\">&nbsp;Change login data:" fullword ascii
    $s16 = "* Please enter new login name." fullword ascii
    $s17 = "echo \"<meta http-equiv=\\\"refresh\\\" content=\\\"1; url=settings.php\\\">\"; " fullword ascii
    $s18 = "<form action=\\\"\" . basename( $_SERVER['SCRIPT_NAME'] ) . \"\\\" method=\\\"post\\\" name=\\\"form\\\">" fullword ascii
    $s19 = "* Please enter observer password." fullword ascii
    $s20 = "* Please enter current CP password." fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 80KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}