rule TTP_XOR_MULT_DOSStub_4123 {
  strings:
    $key_4123 = { 15 4b [2] 61 53 [2] 26 51 [2] 61 40 [2] 2f 4c [2] 23 46 [2] 34 4d [2] 2f 03 [2] 12 }

  condition:
    any of them
}