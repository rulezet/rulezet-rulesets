rule TTP_XOR_MULT_DOSStub_3965 {
  strings:
    $key_3965 = { 6d 0d [2] 19 15 [2] 5e 17 [2] 19 06 [2] 57 0a [2] 5b 00 [2] 4c 0b [2] 57 45 [2] 6a }

  condition:
    any of them
}