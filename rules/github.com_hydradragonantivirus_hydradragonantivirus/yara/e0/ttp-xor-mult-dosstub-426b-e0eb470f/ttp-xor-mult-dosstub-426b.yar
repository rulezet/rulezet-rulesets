rule TTP_XOR_MULT_DOSStub_426b {
  strings:
    $key_426b = { 16 03 [2] 62 1b [2] 25 19 [2] 62 08 [2] 2c 04 [2] 20 0e [2] 37 05 [2] 2c 4b [2] 11 }

  condition:
    any of them
}