rule TTP_XOR_MULT_DOSStub_f5e8 {
  strings:
    $key_f5e8 = { a1 80 [2] d5 98 [2] 92 9a [2] d5 8b [2] 9b 87 [2] 97 8d [2] 80 86 [2] 9b c8 [2] a6 }

  condition:
    any of them
}