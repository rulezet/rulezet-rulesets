rule TTP_XOR_MULT_DOSStub_220d {
  strings:
    $key_220d = { 76 65 [2] 02 7d [2] 45 7f [2] 02 6e [2] 4c 62 [2] 40 68 [2] 57 63 [2] 4c 2d [2] 71 }

  condition:
    any of them
}