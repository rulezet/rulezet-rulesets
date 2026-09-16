rule TTP_XOR_MULT_DOSStub_7171 {
  strings:
    $key_7171 = { 25 19 [2] 51 01 [2] 16 03 [2] 51 12 [2] 1f 1e [2] 13 14 [2] 04 1f [2] 1f 51 [2] 22 }

  condition:
    any of them
}