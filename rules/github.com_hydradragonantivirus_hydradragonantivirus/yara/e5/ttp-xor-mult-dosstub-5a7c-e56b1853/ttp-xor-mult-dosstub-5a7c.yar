rule TTP_XOR_MULT_DOSStub_5a7c {
  strings:
    $key_5a7c = { 0e 14 [2] 7a 0c [2] 3d 0e [2] 7a 1f [2] 34 13 [2] 38 19 [2] 2f 12 [2] 34 5c [2] 09 }

  condition:
    any of them
}