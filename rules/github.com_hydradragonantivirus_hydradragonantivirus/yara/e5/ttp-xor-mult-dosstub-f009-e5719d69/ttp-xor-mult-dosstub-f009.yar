rule TTP_XOR_MULT_DOSStub_f009 {
  strings:
    $key_f009 = { a4 61 [2] d0 79 [2] 97 7b [2] d0 6a [2] 9e 66 [2] 92 6c [2] 85 67 [2] 9e 29 [2] a3 }

  condition:
    any of them
}