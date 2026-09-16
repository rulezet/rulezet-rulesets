rule SUSP_PList_Param_OtherJobEnabled_xor {
  strings:
    $ = "<key>OtherJobEnabled</key>" xor(0x01-0xff)

  condition:
    all of them
}