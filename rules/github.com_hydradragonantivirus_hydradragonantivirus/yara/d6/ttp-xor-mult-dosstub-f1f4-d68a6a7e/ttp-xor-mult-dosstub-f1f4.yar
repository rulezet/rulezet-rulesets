rule TTP_XOR_MULT_DOSStub_f1f4 {
  strings:
    $key_f1f4 = { a5 9c [2] d1 84 [2] 96 86 [2] d1 97 [2] 9f 9b [2] 93 91 [2] 84 9a [2] 9f d4 [2] a2 }

  condition:
    any of them
}