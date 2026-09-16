rule TTP_XOR_MULT_DOSStub_3b74 {
  strings:
    $key_3b74 = { 6f 1c [2] 1b 04 [2] 5c 06 [2] 1b 17 [2] 55 1b [2] 59 11 [2] 4e 1a [2] 55 54 [2] 68 }

  condition:
    any of them
}