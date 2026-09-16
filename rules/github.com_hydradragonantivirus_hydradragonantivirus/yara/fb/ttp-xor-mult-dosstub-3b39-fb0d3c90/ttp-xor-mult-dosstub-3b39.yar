rule TTP_XOR_MULT_DOSStub_3b39 {
  strings:
    $key_3b39 = { 6f 51 [2] 1b 49 [2] 5c 4b [2] 1b 5a [2] 55 56 [2] 59 5c [2] 4e 57 [2] 55 19 [2] 68 }

  condition:
    any of them
}