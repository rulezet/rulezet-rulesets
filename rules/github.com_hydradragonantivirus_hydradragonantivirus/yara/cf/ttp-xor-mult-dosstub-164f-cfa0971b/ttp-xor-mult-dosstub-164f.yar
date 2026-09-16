rule TTP_XOR_MULT_DOSStub_164f {
  strings:
    $key_164f = { 42 27 [2] 36 3f [2] 71 3d [2] 36 2c [2] 78 20 [2] 74 2a [2] 63 21 [2] 78 6f [2] 45 }

  condition:
    any of them
}