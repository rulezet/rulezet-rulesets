rule TTP_XOR_MULT_DOSStub_0257 {
  strings:
    $key_0257 = { 56 3f [2] 22 27 [2] 65 25 [2] 22 34 [2] 6c 38 [2] 60 32 [2] 77 39 [2] 6c 77 [2] 51 }

  condition:
    any of them
}