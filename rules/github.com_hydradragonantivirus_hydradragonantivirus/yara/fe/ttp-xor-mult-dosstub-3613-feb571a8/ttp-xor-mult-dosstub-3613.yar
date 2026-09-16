rule TTP_XOR_MULT_DOSStub_3613 {
  strings:
    $key_3613 = { 62 7b [2] 16 63 [2] 51 61 [2] 16 70 [2] 58 7c [2] 54 76 [2] 43 7d [2] 58 33 [2] 65 }

  condition:
    any of them
}