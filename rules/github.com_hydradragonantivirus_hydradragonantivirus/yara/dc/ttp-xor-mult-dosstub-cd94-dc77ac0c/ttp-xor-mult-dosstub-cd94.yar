rule TTP_XOR_MULT_DOSStub_cd94 {
  strings:
    $key_cd94 = { 99 fc [2] ed e4 [2] aa e6 [2] ed f7 [2] a3 fb [2] af f1 [2] b8 fa [2] a3 b4 [2] 9e }

  condition:
    any of them
}