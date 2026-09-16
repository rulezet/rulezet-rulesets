rule TTP_XOR_MULT_DOSStub_f699 {
  strings:
    $key_f699 = { a2 f1 [2] d6 e9 [2] 91 eb [2] d6 fa [2] 98 f6 [2] 94 fc [2] 83 f7 [2] 98 b9 [2] a5 }

  condition:
    any of them
}