rule TTP_XOR_MULT_DOSStub_0663 {
  strings:
    $key_0663 = { 52 0b [2] 26 13 [2] 61 11 [2] 26 00 [2] 68 0c [2] 64 06 [2] 73 0d [2] 68 43 [2] 55 }

  condition:
    any of them
}