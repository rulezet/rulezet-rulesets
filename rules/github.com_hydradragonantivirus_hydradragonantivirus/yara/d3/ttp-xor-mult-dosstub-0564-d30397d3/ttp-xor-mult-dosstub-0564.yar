rule TTP_XOR_MULT_DOSStub_0564 {
  strings:
    $key_0564 = { 51 0c [2] 25 14 [2] 62 16 [2] 25 07 [2] 6b 0b [2] 67 01 [2] 70 0a [2] 6b 44 [2] 56 }

  condition:
    any of them
}