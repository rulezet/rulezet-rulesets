rule TTP_XOR_MULT_DOSStub_7023 {
  strings:
    $key_7023 = { 24 4b [2] 50 53 [2] 17 51 [2] 50 40 [2] 1e 4c [2] 12 46 [2] 05 4d [2] 1e 03 [2] 23 }

  condition:
    any of them
}