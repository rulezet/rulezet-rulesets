rule TTP_XOR_MULT_DOSStub_7120 {
  strings:
    $key_7120 = { 25 48 [2] 51 50 [2] 16 52 [2] 51 43 [2] 1f 4f [2] 13 45 [2] 04 4e [2] 1f 00 [2] 22 }

  condition:
    any of them
}