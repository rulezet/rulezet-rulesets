rule TTP_XOR_MULT_DOSStub_6a65 {
  strings:
    $key_6a65 = { 3e 0d [2] 4a 15 [2] 0d 17 [2] 4a 06 [2] 04 0a [2] 08 00 [2] 1f 0b [2] 04 45 [2] 39 }

  condition:
    any of them
}