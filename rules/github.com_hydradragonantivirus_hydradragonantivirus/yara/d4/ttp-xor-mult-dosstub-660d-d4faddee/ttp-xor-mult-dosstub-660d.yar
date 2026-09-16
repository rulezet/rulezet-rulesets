rule TTP_XOR_MULT_DOSStub_660d {
  strings:
    $key_660d = { 32 65 [2] 46 7d [2] 01 7f [2] 46 6e [2] 08 62 [2] 04 68 [2] 13 63 [2] 08 2d [2] 35 }

  condition:
    any of them
}