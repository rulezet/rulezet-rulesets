rule TTP_XOR_MULT_DOSStub_c499 {
  strings:
    $key_c499 = { 90 f1 [2] e4 e9 [2] a3 eb [2] e4 fa [2] aa f6 [2] a6 fc [2] b1 f7 [2] aa b9 [2] 97 }

  condition:
    any of them
}