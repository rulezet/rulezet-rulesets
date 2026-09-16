rule TTP_XOR_MULT_DOSStub_3623 {
  strings:
    $key_3623 = { 62 4b [2] 16 53 [2] 51 51 [2] 16 40 [2] 58 4c [2] 54 46 [2] 43 4d [2] 58 03 [2] 65 }

  condition:
    any of them
}