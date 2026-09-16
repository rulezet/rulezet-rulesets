rule TTP_XOR_MULT_DOSStub_161d {
  strings:
    $key_161d = { 42 75 [2] 36 6d [2] 71 6f [2] 36 7e [2] 78 72 [2] 74 78 [2] 63 73 [2] 78 3d [2] 45 }

  condition:
    any of them
}