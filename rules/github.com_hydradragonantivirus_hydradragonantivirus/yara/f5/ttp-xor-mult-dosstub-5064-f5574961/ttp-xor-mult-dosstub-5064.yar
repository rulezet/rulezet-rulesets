rule TTP_XOR_MULT_DOSStub_5064 {
  strings:
    $key_5064 = { 04 0c [2] 70 14 [2] 37 16 [2] 70 07 [2] 3e 0b [2] 32 01 [2] 25 0a [2] 3e 44 [2] 03 }

  condition:
    any of them
}