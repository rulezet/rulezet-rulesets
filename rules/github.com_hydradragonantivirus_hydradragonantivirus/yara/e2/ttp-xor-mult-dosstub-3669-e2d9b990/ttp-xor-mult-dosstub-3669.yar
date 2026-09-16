rule TTP_XOR_MULT_DOSStub_3669 {
  strings:
    $key_3669 = { 62 01 [2] 16 19 [2] 51 1b [2] 16 0a [2] 58 06 [2] 54 0c [2] 43 07 [2] 58 49 [2] 65 }

  condition:
    any of them
}