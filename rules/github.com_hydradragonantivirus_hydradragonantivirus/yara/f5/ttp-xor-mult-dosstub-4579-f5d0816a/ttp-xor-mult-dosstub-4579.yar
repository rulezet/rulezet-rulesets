rule TTP_XOR_MULT_DOSStub_4579 {
  strings:
    $key_4579 = { 11 11 [2] 65 09 [2] 22 0b [2] 65 1a [2] 2b 16 [2] 27 1c [2] 30 17 [2] 2b 59 [2] 16 }

  condition:
    any of them
}