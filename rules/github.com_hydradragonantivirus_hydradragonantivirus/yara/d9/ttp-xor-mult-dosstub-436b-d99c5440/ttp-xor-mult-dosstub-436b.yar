rule TTP_XOR_MULT_DOSStub_436b {
  strings:
    $key_436b = { 17 03 [2] 63 1b [2] 24 19 [2] 63 08 [2] 2d 04 [2] 21 0e [2] 36 05 [2] 2d 4b [2] 10 }

  condition:
    any of them
}