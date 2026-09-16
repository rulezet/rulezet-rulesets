rule TTP_XOR_MULT_DOSStub_574f {
  strings:
    $key_574f = { 03 27 [2] 77 3f [2] 30 3d [2] 77 2c [2] 39 20 [2] 35 2a [2] 22 21 [2] 39 6f [2] 04 }

  condition:
    any of them
}