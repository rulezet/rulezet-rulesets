rule infected_01_29_19_amadey_botnet_index {
  meta:
    description = "amadey-botnet - file index.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-01-30"
    hash1       = "2f6fc95474a13f99405a9fa327401e908a2bbe39865d8cb881418207faac63a4"

  strings:
    $s1  = "$sql = mysql_query( \"SELECT * FROM `tasks` WHERE `status`='1' AND `id` NOT IN ( SELECT `task_id` FROM `tasks_exec` WHERE " fullword ascii
    $s2  = "header( \"Refresh: 1; url = login.php\" );" fullword ascii
    $s3  = "mysql_query( \"INSERT `tasks_exec` VALUES ( null, '\" . $task['id'] . \"', '\" . $unit_id . \"', '1' )\" );" fullword ascii
    $s4  = "mysql_query( \"UPDATE `tasks` SET `loads`=`loads` + 1, `status`= IF (`loads` >= `tlimit` and `tlimit` <> 0 ,0 , `status` )  WH" fullword ascii
    $s5  = "IncreaseCount( $_POST[\"d1\"] , \"exec\" );" fullword ascii
    $s6  = "$geoip = geo_ip::getInstance( \"f.st/geo_ip.dat\" );" fullword ascii
    $s7  = "mysql_connect( $conf[\"dbhost\"], $conf[\"dbuser\"], $conf[\"dbpass\"] );" fullword ascii
    $s8  = "mysql_query( \"INSERT INTO units ( id, ip, first_ip, online, country, ar, arch, version, os, av, pc, un, reg ) VALUES (" fullword ascii
    $s9  = "echo \"<c>\" . GetTaskContent( $_POST[\"id\"] ) . \"<d>\";" fullword ascii
    $s10 = "`unitid`='\" . $unit_id . \"' AND `exec`='1' ) ORDER BY id ASC\" ); " fullword ascii
    $s11 = "mysql_query( \"UPDATE `tasks` SET `$type` = `$type` + 1 WHERE `id` = '\" . $taskid . \"' LIMIT 1\" );" fullword ascii
    $s12 = "elseif ( !empty( $_SERVER[\"HTTP_X_FORWARDED_FOR\"] ) ) " fullword ascii
    $s13 = "list( $id, $online ) = mysql_fetch_array( mysql_query( \"SELECT id, online FROM units WHERE id = '$bot_id' LIMIT 1\" ) );  " fullword ascii
    $s14 = "$res .= $task['id'] . $task['run'] . $task['filetype'] . $task['autorun'] . $task['path'] . \"#\";" fullword ascii
    $s15 = "function GetTaskContent( $unit_id ) " fullword ascii
    $s16 = "mysql_query( \"UPDATE units SET ip = '$bot_ip', online = '$time', country = '$country', ar = '$ar', arch = '$bi', versi" fullword ascii
    $s17 = "IncreaseCount( $_POST[\"e1\"] , \"error2\" );" fullword ascii
    $s18 = "IncreaseCount( $_POST[\"e0\"] , \"error\" );" fullword ascii
    $s19 = "$ip = $_SERVER[\"HTTP_X_FORWARDED_FOR\"];" fullword ascii
    $s20 = "return $geoip -> lookupCountryName( $ip );" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 20KB and
      (8 of them)
    ) or (all of them)
}