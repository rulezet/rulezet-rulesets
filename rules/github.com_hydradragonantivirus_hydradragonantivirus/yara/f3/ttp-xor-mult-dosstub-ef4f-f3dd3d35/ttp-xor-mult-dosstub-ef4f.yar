rule TTP_XOR_MULT_DOSStub_ef4f {
  strings:
    $key_ef4f = { bb 27 [2] cf 3f [2] 88 3d [2] cf 2c [2] 81 20 [2] 8d 2a [2] 9a 21 [2] 81 6f [2] bc }

  condition:
    any of them
}