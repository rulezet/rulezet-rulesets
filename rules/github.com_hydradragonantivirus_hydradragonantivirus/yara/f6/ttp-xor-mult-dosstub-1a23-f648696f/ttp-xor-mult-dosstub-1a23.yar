rule TTP_XOR_MULT_DOSStub_1a23 {
  strings:
    $key_1a23 = { 4e 4b [2] 3a 53 [2] 7d 51 [2] 3a 40 [2] 74 4c [2] 78 46 [2] 6f 4d [2] 74 03 [2] 49 }

  condition:
    any of them
}