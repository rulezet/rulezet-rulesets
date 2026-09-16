rule TTP_XOR_MULT_DOSStub_3b25 {
  strings:
    $key_3b25 = { 6f 4d [2] 1b 55 [2] 5c 57 [2] 1b 46 [2] 55 4a [2] 59 40 [2] 4e 4b [2] 55 05 [2] 68 }

  condition:
    any of them
}