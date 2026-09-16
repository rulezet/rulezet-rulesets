rule TTP_XOR_MULT_DOSStub_4a23 {
  strings:
    $key_4a23 = { 1e 4b [2] 6a 53 [2] 2d 51 [2] 6a 40 [2] 24 4c [2] 28 46 [2] 3f 4d [2] 24 03 [2] 19 }

  condition:
    any of them
}