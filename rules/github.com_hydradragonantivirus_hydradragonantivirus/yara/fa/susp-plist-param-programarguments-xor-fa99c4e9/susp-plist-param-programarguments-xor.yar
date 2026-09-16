rule SUSP_PList_Param_ProgramArguments_xor {
  strings:
    $ = "<key>ProgramArguments</key>" xor(0x01-0xff)

  condition:
    all of them
}