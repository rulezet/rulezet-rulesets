rule TTP_XOR_MULT_DOSStub_3b08 {
  strings:
    $key_3b08 = { 6f 60 [2] 1b 78 [2] 5c 7a [2] 1b 6b [2] 55 67 [2] 59 6d [2] 4e 66 [2] 55 28 [2] 68 }

  condition:
    any of them
}