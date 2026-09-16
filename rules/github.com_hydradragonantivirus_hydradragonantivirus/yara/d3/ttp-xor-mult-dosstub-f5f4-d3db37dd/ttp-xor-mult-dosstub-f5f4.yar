rule TTP_XOR_MULT_DOSStub_f5f4 {
  strings:
    $key_f5f4 = { a1 9c [2] d5 84 [2] 92 86 [2] d5 97 [2] 9b 9b [2] 97 91 [2] 80 9a [2] 9b d4 [2] a6 }

  condition:
    any of them
}