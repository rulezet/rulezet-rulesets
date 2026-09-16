rule TTP_XOR_MULT_DOSStub_5750 {
  strings:
    $key_5750 = { 03 38 [2] 77 20 [2] 30 22 [2] 77 33 [2] 39 3f [2] 35 35 [2] 22 3e [2] 39 70 [2] 04 }

  condition:
    any of them
}