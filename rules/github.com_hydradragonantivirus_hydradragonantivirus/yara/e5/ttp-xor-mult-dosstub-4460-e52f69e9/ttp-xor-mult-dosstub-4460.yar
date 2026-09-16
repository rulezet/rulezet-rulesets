rule TTP_XOR_MULT_DOSStub_4460 {
  strings:
    $key_4460 = { 10 08 [2] 64 10 [2] 23 12 [2] 64 03 [2] 2a 0f [2] 26 05 [2] 31 0e [2] 2a 40 [2] 17 }

  condition:
    any of them
}