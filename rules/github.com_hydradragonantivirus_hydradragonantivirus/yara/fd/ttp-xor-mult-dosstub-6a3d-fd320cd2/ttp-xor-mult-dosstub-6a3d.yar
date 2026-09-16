rule TTP_XOR_MULT_DOSStub_6a3d {
  strings:
    $key_6a3d = { 3e 55 [2] 4a 4d [2] 0d 4f [2] 4a 5e [2] 04 52 [2] 08 58 [2] 1f 53 [2] 04 1d [2] 39 }

  condition:
    any of them
}