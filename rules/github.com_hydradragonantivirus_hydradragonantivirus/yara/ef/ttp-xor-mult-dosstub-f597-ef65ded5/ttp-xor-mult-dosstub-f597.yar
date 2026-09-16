rule TTP_XOR_MULT_DOSStub_f597 {
  strings:
    $key_f597 = { a1 ff [2] d5 e7 [2] 92 e5 [2] d5 f4 [2] 9b f8 [2] 97 f2 [2] 80 f9 [2] 9b b7 [2] a6 }

  condition:
    any of them
}