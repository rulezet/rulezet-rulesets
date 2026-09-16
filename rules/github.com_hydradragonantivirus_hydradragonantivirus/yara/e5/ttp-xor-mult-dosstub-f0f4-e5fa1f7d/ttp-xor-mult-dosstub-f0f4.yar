rule TTP_XOR_MULT_DOSStub_f0f4 {
  strings:
    $key_f0f4 = { a4 9c [2] d0 84 [2] 97 86 [2] d0 97 [2] 9e 9b [2] 92 91 [2] 85 9a [2] 9e d4 [2] a3 }

  condition:
    any of them
}