rule TTP_XOR_MULT_DOSStub_6d5d {
  strings:
    $key_6d5d = { 39 35 [2] 4d 2d [2] 0a 2f [2] 4d 3e [2] 03 32 [2] 0f 38 [2] 18 33 [2] 03 7d [2] 3e }

  condition:
    any of them
}