rule SUSP_PList_Param_ProgramArguments_base64 {
  strings:
    $ = "<key>ProgramArguments</key>" base64 base64wide

  condition:
    all of them
}