rule edit_task {
  meta:
    description = "amadey-botnet - file edit_task.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-01-30"
    hash1       = "fb691c2e788044320bcf49811c45d7813e3fa62941ee5b9d4ebc05e53db9a0f4"

  strings:
    $x1  = "* Chosen country, * for any. <a href=\\\"images/task_example.png\\\" target=\\\"_blank\\\">Exampl" fullword ascii
    $s2  = "e</a>. <a href=\\\"f.st\\c.index.txt\\\" target=\\\"_blank\\\">Countries <b>index</b> table</a>." fullword ascii
    $s3  = "MakeTask( $_POST['path']  . \":::\" . $_POST['dllfunction'], \"0\", $_POST['filetype'], $_POST['autorun'], $_POST['count']" fullword ascii
    $s4  = "* Chosen country, * for any. <a href=\\\"images/task_example.png\\\" target=\\\"_blank\\\">Example</a>. <a href=\\\"f.st\\c.inde" ascii
    $s5  = "MakeTask( $_POST['path'], $_POST['run'], $_POST['filetype'], $_POST['autorun'], $_POST['count'], $_POST['unitid'], $_P" fullword ascii
    $s6  = "echo \"<meta http-equiv=\\\"refresh\\\" content=\\\"1; url=show_tasks.php\\\">\"; " fullword ascii
    $s7  = "* Startup options, <b>only for EXE</b>. Warning! Do not change this option if you don't know what it is." fullword ascii
    $s8  = "<form action=\\\"\" . basename( $_SERVER['SCRIPT_NAME'] ) . \"\\\" method=\\\"post\\\" name=\\\"form\\\">" fullword ascii
    $s9  = "header( \"Location: login.php\" );" fullword ascii
    $s10 = "* Startup options, <b>only for EXE</b>. Warning! Do not change this option if you don't k" fullword ascii
    $s11 = "mysql_query( \"UPDATE `tasks` SET `path` = '$url', `run` = '$run', `filetype` = '$filetype', `autorun` = '$autorun', `tlim" fullword ascii
    $s12 = "$sql = mysql_query( \"SELECT * FROM tasks WHERE id = '$id' LIMIT 1\" ) or die(mysql_error());" fullword ascii
    $s13 = "* Web URL, file will be saved with original name, expansion will be changed." fullword ascii
    $s14 = "mysql_connect($conf['dbhost'], $conf['dbuser'], $conf['dbpass'] ); " fullword ascii
    $s15 = "* Name of the calling function, <b>only for DLL</b>." fullword ascii
    $s16 = ", $_POST['unitid'], $_POST['country'], $_POST['id'], $_POST['ctlimit'] ); " fullword ascii
    $s17 = "function MakeTask( $url, $run, $filetype, $autorun, $limit, $units, $country, $id, $ctlimit ) " fullword ascii
    $s18 = "it` = '$limit', `path` = '$url', `units` = '$units', `country` = '$country' WHERE `id` = '\".$id.\"' LIMIT 1\" );" fullword ascii
    $s19 = "echo \"Please login at root, observers cant edit task\"; " fullword ascii
    $s20 = "<input name=\\\"dllfunction\\\" class=task value=\\\"\" . $dllfunction . \"\\\" style=\\\"float: left\\\">" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 30KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}