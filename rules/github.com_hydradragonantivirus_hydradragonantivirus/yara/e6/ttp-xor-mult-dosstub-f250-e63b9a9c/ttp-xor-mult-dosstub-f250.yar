rule TTP_XOR_MULT_DOSStub_f250 {
  strings:
    $key_f250 = { a6 38 [2] d2 20 [2] 95 22 [2] d2 33 [2] 9c 3f [2] 90 35 [2] 87 3e [2] 9c 70 [2] a1 }

  condition:
    any of them
}