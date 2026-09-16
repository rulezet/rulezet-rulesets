rule TTP_XOR_MULT_DOSStub_e764 {
  strings:
    $key_e764 = { b3 0c [2] c7 14 [2] 80 16 [2] c7 07 [2] 89 0b [2] 85 01 [2] 92 0a [2] 89 44 [2] b4 }

  condition:
    any of them
}