rule TTP_XOR_MULT_DOSStub_617d {
  strings:
    $key_617d = { 35 15 [2] 41 0d [2] 06 0f [2] 41 1e [2] 0f 12 [2] 03 18 [2] 14 13 [2] 0f 5d [2] 32 }

  condition:
    any of them
}