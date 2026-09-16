rule TTP_XOR_MULT_DOSStub_4021 {
  strings:
    $key_4021 = { 14 49 [2] 60 51 [2] 27 53 [2] 60 42 [2] 2e 4e [2] 22 44 [2] 35 4f [2] 2e 01 [2] 13 }

  condition:
    any of them
}