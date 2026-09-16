rule TTP_XOR_MULT_DOSStub_f994 {
  strings:
    $key_f994 = { ad fc [2] d9 e4 [2] 9e e6 [2] d9 f7 [2] 97 fb [2] 9b f1 [2] 8c fa [2] 97 b4 [2] aa }

  condition:
    any of them
}