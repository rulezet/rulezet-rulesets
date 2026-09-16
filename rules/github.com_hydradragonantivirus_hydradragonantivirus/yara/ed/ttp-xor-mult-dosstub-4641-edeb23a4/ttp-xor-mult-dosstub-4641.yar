rule TTP_XOR_MULT_DOSStub_4641 {
  strings:
    $key_4641 = { 12 29 [2] 66 31 [2] 21 33 [2] 66 22 [2] 28 2e [2] 24 24 [2] 33 2f [2] 28 61 [2] 15 }

  condition:
    any of them
}