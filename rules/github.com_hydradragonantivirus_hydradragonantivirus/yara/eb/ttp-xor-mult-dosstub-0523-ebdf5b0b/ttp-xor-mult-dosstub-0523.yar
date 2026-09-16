rule TTP_XOR_MULT_DOSStub_0523 {
  strings:
    $key_0523 = { 51 4b [2] 25 53 [2] 62 51 [2] 25 40 [2] 6b 4c [2] 67 46 [2] 70 4d [2] 6b 03 [2] 56 }

  condition:
    any of them
}