rule _TryagFileManager3_shell_php_1 {
  meta:
    description = "Tryag-File-Manager-jpeg-master - from files TryagFileManager3.php, shell.php.pjpeg"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-07-14"
    hash1       = "3cf5af7774d1dc7ca7b58d9d6899ef307eabb9ed9b66d4ef0eb44cd346135bd8"
    hash2       = "cb2241fd794aaff55b354114d1447e3e6411619ca257316807cb6d0d59651021"

  strings:
        $s2 = "echo '<div id=\"content\"><table width=\"700\" border=\"0\" cellpadding=\"3\" cellspacing=\"1\" align=\"center\">" fullword ascii
    $s3 = "if(is_writable(\"$path/$file\") || !is_readable(\"$path/$file\")) echo '</font>';" fullword ascii
                                  
  condition:
    (uint16(0) == 0x3f3c and
      filesize < 30KB and (8 of them)
    ) or (all of them)
}