rule INFO_PList_Param_Umask {
  strings:
    $ = "<key>Umask</key>" ascii wide

  condition:
    all of them
}