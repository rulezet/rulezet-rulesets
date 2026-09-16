rule TTP_XOR_MULT_DOSStub_3f48 {
  strings:
    $key_3f48 = { 6b 20 [2] 1f 38 [2] 58 3a [2] 1f 2b [2] 51 27 [2] 5d 2d [2] 4a 26 [2] 51 68 [2] 6c }

  condition:
    any of them
}