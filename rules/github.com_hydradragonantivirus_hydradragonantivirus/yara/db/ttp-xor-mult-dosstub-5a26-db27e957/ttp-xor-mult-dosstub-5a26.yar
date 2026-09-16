rule TTP_XOR_MULT_DOSStub_5a26 {
  strings:
    $key_5a26 = { 0e 4e [2] 7a 56 [2] 3d 54 [2] 7a 45 [2] 34 49 [2] 38 43 [2] 2f 48 [2] 34 06 [2] 09 }

  condition:
    any of them
}