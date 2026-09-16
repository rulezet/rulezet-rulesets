rule TTP_XOR_MULT_DOSStub_1f45 {
  strings:
    $key_1f45 = { 4b 2d [2] 3f 35 [2] 78 37 [2] 3f 26 [2] 71 2a [2] 7d 20 [2] 6a 2b [2] 71 65 [2] 4c }

  condition:
    any of them
}