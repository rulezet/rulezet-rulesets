rule TTP_XOR_MULT_DOSStub_6171 {
  strings:
    $key_6171 = { 35 19 [2] 41 01 [2] 06 03 [2] 41 12 [2] 0f 1e [2] 03 14 [2] 14 1f [2] 0f 51 [2] 32 }

  condition:
    any of them
}