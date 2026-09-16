rule TTP_XOR_MULT_DOSStub_3071 {
  strings:
    $key_3071 = { 64 19 [2] 10 01 [2] 57 03 [2] 10 12 [2] 5e 1e [2] 52 14 [2] 45 1f [2] 5e 51 [2] 63 }

  condition:
    any of them
}