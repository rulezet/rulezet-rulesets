rule SUSP_PList_Param_StartOnMount_base64 {
  strings:
    $ = "<key>StartOnMount</key>" base64 base64wide

  condition:
    all of them
}