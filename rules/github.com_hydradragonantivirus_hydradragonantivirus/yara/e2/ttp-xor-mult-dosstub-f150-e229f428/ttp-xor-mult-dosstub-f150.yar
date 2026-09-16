rule TTP_XOR_MULT_DOSStub_f150 {
  strings:
    $key_f150 = { a5 38 [2] d1 20 [2] 96 22 [2] d1 33 [2] 9f 3f [2] 93 35 [2] 84 3e [2] 9f 70 [2] a2 }

  condition:
    any of them
}