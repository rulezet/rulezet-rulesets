rule TTP_XOR_MULT_DOSStub_4a10 {
  strings:
    $key_4a10 = { 1e 78 [2] 6a 60 [2] 2d 62 [2] 6a 73 [2] 24 7f [2] 28 75 [2] 3f 7e [2] 24 30 [2] 19 }

  condition:
    any of them
}