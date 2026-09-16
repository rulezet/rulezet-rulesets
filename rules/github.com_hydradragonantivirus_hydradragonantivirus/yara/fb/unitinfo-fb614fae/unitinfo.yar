rule unitinfo {
  meta:
    description = "amadey-botnet - file unitinfo.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-01-30"
    hash1       = "d65a0cb6f9ac091e68aea1e8606263ac47ca7b38b59597905aa15cfcc513376e"

  strings:
    $x1  = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_8.png\\\"> \" . \"Operation system:\" . \"</td>\"; " fullword ascii
    $s2  = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_14.png\\\"> \" . \"Host name:\" . \"</td>\"; " fullword ascii
    $s3  = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_15.png\\\"> \" . \"User name:\" . \"</td>\"; " fullword ascii
    $s4  = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_12.png\\\"> \" . \"Last IP address:\" . \"</td>\"; " fullword ascii
    $s5  = "echo \"SQL connection filed, check host, name, login and password\";" fullword ascii
    $s6  = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_6.png\\\"> \" . \"Version:\" . \"</td>\"; " fullword ascii
    $s7  = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_10.png\\\"> \" . \"Access rights:\" . \"</td>\"; " fullword ascii
    $s8  = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_6.png\\\"> \" . \"Received tasks:\" . \"</td>\"; " fullword ascii
    $s9  = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_11.png\\\"> \" . \"Last seen:\" . \"</td>\"; " fullword ascii
    $s10 = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_av.png\\\"> \" . \"Antiviral kit:\" . \"</td>\"; " fullword ascii
    $s11 = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_13.png\\\"> \" . \"Country:\" . \"</td>\"; " fullword ascii
    $s12 = "$result = mysql_query( 'SELECT * FROM tasks_exec WHERE unitid = ' . $id );" fullword ascii
    $s13 = "header( \"Location: login.php\" );" fullword ascii
    $s14 = "if ( @mysql_connect( $conf['dbhost'], $conf['dbuser'], $conf['dbpass'] ) == false )" fullword ascii
    $s15 = "\"<td bgcolor = \" . $gb . \">\" . \"<div align = left>\" . \"<img src=\\\"images\\ic_3.png\\\"> \" . \"<a href=\\\"\" " fullword ascii
    $s16 = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_9.png\\\"> \" . \"Operation system architecture:\" ." ascii
    $s17 = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_9.png\\\"> \" . \"Operation system architecture:\" ." ascii
    $s18 = "\"<td bgcolor = \" . $gb . \">\" . \"<div align = left>&nbsp;<img src=\\\"images\\ic_1.png\\\"> \" . $r['id'] . \"" fullword ascii
    $s19 = "echo \"    <td width=200 bgcolor =\"  . $gb . \"><b>\" . GetUnitData( $i, 'version' ) . \"</b></td></tr>\";" fullword ascii
    $s20 = "@mysql_connect( $conf['dbhost'], $conf['dbuser'], $conf['dbpass'] );" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 20KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}