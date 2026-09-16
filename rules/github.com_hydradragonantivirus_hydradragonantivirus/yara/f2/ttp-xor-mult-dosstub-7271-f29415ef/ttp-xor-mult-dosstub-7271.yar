rule TTP_XOR_MULT_DOSStub_7271 {
  strings:
    $key_7271 = { 26 19 [2] 52 01 [2] 15 03 [2] 52 12 [2] 1c 1e [2] 10 14 [2] 07 1f [2] 1c 51 [2] 21 }

  condition:
    any of them
}