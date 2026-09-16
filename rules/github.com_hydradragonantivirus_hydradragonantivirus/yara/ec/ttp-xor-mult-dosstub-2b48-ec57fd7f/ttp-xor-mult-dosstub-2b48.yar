rule TTP_XOR_MULT_DOSStub_2b48 {
  strings:
    $key_2b48 = { 7f 20 [2] 0b 38 [2] 4c 3a [2] 0b 2b [2] 45 27 [2] 49 2d [2] 5e 26 [2] 45 68 [2] 78 }

  condition:
    any of them
}