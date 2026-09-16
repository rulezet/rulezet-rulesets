rule TTP_XOR_MULT_DOSStub_6a45 {
  strings:
    $key_6a45 = { 3e 2d [2] 4a 35 [2] 0d 37 [2] 4a 26 [2] 04 2a [2] 08 20 [2] 1f 2b [2] 04 65 [2] 39 }

  condition:
    any of them
}