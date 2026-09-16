rule TTP_XOR_MULT_DOSStub_2671 {
  strings:
    $key_2671 = { 72 19 [2] 06 01 [2] 41 03 [2] 06 12 [2] 48 1e [2] 44 14 [2] 53 1f [2] 48 51 [2] 75 }

  condition:
    any of them
}