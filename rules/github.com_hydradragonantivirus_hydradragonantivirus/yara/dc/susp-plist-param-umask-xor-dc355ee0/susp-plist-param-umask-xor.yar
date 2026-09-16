rule SUSP_PList_Param_Umask_xor {
  strings:
    $ = "<key>Umask</key>" xor(0x01-0xff)

  condition:
    all of them
}