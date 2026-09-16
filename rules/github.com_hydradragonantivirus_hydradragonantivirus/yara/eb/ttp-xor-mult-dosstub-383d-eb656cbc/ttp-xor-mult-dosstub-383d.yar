rule TTP_XOR_MULT_DOSStub_383d {
  strings:
    $key_383d = { 6c 55 [2] 18 4d [2] 5f 4f [2] 18 5e [2] 56 52 [2] 5a 58 [2] 4d 53 [2] 56 1d [2] 6b }

  condition:
    any of them
}