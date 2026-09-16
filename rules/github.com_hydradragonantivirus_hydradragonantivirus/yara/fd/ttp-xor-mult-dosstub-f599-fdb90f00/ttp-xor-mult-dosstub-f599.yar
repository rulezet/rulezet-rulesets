rule TTP_XOR_MULT_DOSStub_f599 {
  strings:
    $key_f599 = { a1 f1 [2] d5 e9 [2] 92 eb [2] d5 fa [2] 9b f6 [2] 97 fc [2] 80 f7 [2] 9b b9 [2] a6 }

  condition:
    any of them
}