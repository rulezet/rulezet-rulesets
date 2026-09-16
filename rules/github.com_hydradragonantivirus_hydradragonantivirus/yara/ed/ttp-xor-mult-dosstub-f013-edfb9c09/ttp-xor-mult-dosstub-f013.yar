rule TTP_XOR_MULT_DOSStub_f013 {
  strings:
    $key_f013 = { a4 7b [2] d0 63 [2] 97 61 [2] d0 70 [2] 9e 7c [2] 92 76 [2] 85 7d [2] 9e 33 [2] a3 }

  condition:
    any of them
}