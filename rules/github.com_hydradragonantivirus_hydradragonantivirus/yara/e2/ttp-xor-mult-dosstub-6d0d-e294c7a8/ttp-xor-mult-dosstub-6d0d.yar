rule TTP_XOR_MULT_DOSStub_6d0d {
  strings:
    $key_6d0d = { 39 65 [2] 4d 7d [2] 0a 7f [2] 4d 6e [2] 03 62 [2] 0f 68 [2] 18 63 [2] 03 2d [2] 3e }

  condition:
    any of them
}