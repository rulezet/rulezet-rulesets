rule TTP_XOR_MULT_DOSStub_ef94 {
  strings:
    $key_ef94 = { bb fc [2] cf e4 [2] 88 e6 [2] cf f7 [2] 81 fb [2] 8d f1 [2] 9a fa [2] 81 b4 [2] bc }

  condition:
    any of them
}