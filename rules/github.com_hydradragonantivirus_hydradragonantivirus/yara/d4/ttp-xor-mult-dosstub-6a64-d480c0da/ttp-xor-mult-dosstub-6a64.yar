rule TTP_XOR_MULT_DOSStub_6a64 {
  strings:
    $key_6a64 = { 3e 0c [2] 4a 14 [2] 0d 16 [2] 4a 07 [2] 04 0b [2] 08 01 [2] 1f 0a [2] 04 44 [2] 39 }

  condition:
    any of them
}