rule TTP_XOR_MULT_DOSStub_7966 {
  strings:
    $key_7966 = { 2d 0e [2] 59 16 [2] 1e 14 [2] 59 05 [2] 17 09 [2] 1b 03 [2] 0c 08 [2] 17 46 [2] 2a }

  condition:
    any of them
}