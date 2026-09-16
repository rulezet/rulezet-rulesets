rule TTP_XOR_MULT_DOSStub_6a68 {
  strings:
    $key_6a68 = { 3e 00 [2] 4a 18 [2] 0d 1a [2] 4a 0b [2] 04 07 [2] 08 0d [2] 1f 06 [2] 04 48 [2] 39 }

  condition:
    any of them
}