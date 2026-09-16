rule TTP_XOR_MULT_DOSStub_f245 {
  strings:
    $key_f245 = { a6 2d [2] d2 35 [2] 95 37 [2] d2 26 [2] 9c 2a [2] 90 20 [2] 87 2b [2] 9c 65 [2] a1 }

  condition:
    any of them
}