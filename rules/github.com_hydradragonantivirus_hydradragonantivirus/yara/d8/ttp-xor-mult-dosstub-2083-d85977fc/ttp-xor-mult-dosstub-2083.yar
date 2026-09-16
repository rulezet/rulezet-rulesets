rule TTP_XOR_MULT_DOSStub_2083 {
  strings:
    $key_2083 = { 74 eb [2] 00 f3 [2] 47 f1 [2] 00 e0 [2] 4e ec [2] 42 e6 [2] 55 ed [2] 4e a3 [2] 73 }

  condition:
    any of them
}