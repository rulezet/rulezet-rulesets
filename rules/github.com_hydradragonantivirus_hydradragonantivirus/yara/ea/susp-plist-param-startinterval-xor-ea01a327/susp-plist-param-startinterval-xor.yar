rule SUSP_PList_Param_StartInterval_xor {
  strings:
    $ = "<key>StartInterval</key>" xor(0x01-0xff)

  condition:
    all of them
}