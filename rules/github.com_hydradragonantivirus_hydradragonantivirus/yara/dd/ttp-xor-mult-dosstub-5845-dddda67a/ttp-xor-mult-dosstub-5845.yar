rule TTP_XOR_MULT_DOSStub_5845 {
  strings:
    $key_5845 = { 0c 2d [2] 78 35 [2] 3f 37 [2] 78 26 [2] 36 2a [2] 3a 20 [2] 2d 2b [2] 36 65 [2] 0b }

  condition:
    any of them
}