rule TTP_XOR_MULT_DOSStub_f59b {
  strings:
    $key_f59b = { a1 f3 [2] d5 eb [2] 92 e9 [2] d5 f8 [2] 9b f4 [2] 97 fe [2] 80 f5 [2] 9b bb [2] a6 }

  condition:
    any of them
}