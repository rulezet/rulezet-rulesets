rule TTP_XOR_MULT_DOSStub_b994 {
  strings:
    $key_b994 = { ed fc [2] 99 e4 [2] de e6 [2] 99 f7 [2] d7 fb [2] db f1 [2] cc fa [2] d7 b4 [2] ea }

  condition:
    any of them
}