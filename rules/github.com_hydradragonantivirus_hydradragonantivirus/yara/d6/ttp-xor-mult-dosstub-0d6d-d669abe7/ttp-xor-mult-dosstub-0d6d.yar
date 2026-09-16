rule TTP_XOR_MULT_DOSStub_0d6d {
  strings:
    $key_0d6d = { 59 05 [2] 2d 1d [2] 6a 1f [2] 2d 0e [2] 63 02 [2] 6f 08 [2] 78 03 [2] 63 4d [2] 5e }

  condition:
    any of them
}