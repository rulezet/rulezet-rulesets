rule TTP_XOR_MULT_DOSStub_3f45 {
  strings:
    $key_3f45 = { 6b 2d [2] 1f 35 [2] 58 37 [2] 1f 26 [2] 51 2a [2] 5d 20 [2] 4a 2b [2] 51 65 [2] 6c }

  condition:
    any of them
}