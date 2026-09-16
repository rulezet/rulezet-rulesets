rule TTP_XOR_MULT_DOSStub_ec3d {
  strings:
    $key_ec3d = { b8 55 [2] cc 4d [2] 8b 4f [2] cc 5e [2] 82 52 [2] 8e 58 [2] 99 53 [2] 82 1d [2] bf }

  condition:
    any of them
}