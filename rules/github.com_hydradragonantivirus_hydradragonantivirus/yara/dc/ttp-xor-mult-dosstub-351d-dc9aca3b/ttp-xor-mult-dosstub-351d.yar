rule TTP_XOR_MULT_DOSStub_351d {
  strings:
    $key_351d = { 61 75 [2] 15 6d [2] 52 6f [2] 15 7e [2] 5b 72 [2] 57 78 [2] 40 73 [2] 5b 3d [2] 66 }

  condition:
    any of them
}