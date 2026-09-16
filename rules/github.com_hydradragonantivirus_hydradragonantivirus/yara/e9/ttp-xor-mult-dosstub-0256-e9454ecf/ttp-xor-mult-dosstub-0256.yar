rule TTP_XOR_MULT_DOSStub_0256 {
  strings:
    $key_0256 = { 56 3e [2] 22 26 [2] 65 24 [2] 22 35 [2] 6c 39 [2] 60 33 [2] 77 38 [2] 6c 76 [2] 51 }

  condition:
    any of them
}