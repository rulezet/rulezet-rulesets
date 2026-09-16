rule TTP_XOR_MULT_DOSStub_3771 {
  strings:
    $key_3771 = { 63 19 [2] 17 01 [2] 50 03 [2] 17 12 [2] 59 1e [2] 55 14 [2] 42 1f [2] 59 51 [2] 64 }

  condition:
    any of them
}