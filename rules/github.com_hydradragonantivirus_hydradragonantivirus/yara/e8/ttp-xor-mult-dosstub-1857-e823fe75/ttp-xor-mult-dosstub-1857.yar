rule TTP_XOR_MULT_DOSStub_1857 {
  strings:
    $key_1857 = { 4c 3f [2] 38 27 [2] 7f 25 [2] 38 34 [2] 76 38 [2] 7a 32 [2] 6d 39 [2] 76 77 [2] 4b }

  condition:
    any of them
}