rule TTP_XOR_MULT_DOSStub_3b45 {
  strings:
    $key_3b45 = { 6f 2d [2] 1b 35 [2] 5c 37 [2] 1b 26 [2] 55 2a [2] 59 20 [2] 4e 2b [2] 55 65 [2] 68 }

  condition:
    any of them
}