rule TTP_XOR_MULT_DOSStub_1357 {
  strings:
    $key_1357 = { 47 3f [2] 33 27 [2] 74 25 [2] 33 34 [2] 7d 38 [2] 71 32 [2] 66 39 [2] 7d 77 [2] 40 }

  condition:
    any of them
}