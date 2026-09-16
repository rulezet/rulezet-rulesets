rule TTP_XOR_MULT_DOSStub_5a10 {
  strings:
    $key_5a10 = { 0e 78 [2] 7a 60 [2] 3d 62 [2] 7a 73 [2] 34 7f [2] 38 75 [2] 2f 7e [2] 34 30 [2] 09 }

  condition:
    any of them
}