rule TTP_XOR_MULT_DOSStub_50e8 {
  strings:
    $key_50e8 = { 04 80 [2] 70 98 [2] 37 9a [2] 70 8b [2] 3e 87 [2] 32 8d [2] 25 86 [2] 3e c8 [2] 03 }

  condition:
    any of them
}