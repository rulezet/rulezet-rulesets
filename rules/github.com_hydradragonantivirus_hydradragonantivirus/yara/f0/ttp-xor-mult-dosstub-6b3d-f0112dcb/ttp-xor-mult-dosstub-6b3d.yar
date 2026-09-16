rule TTP_XOR_MULT_DOSStub_6b3d {
  strings:
    $key_6b3d = { 3f 55 [2] 4b 4d [2] 0c 4f [2] 4b 5e [2] 05 52 [2] 09 58 [2] 1e 53 [2] 05 1d [2] 38 }

  condition:
    any of them
}