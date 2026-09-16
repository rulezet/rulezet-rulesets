rule TTP_XOR_MULT_DOSStub_1321 {
  strings:
    $key_1321 = { 47 49 [2] 33 51 [2] 74 53 [2] 33 42 [2] 7d 4e [2] 71 44 [2] 66 4f [2] 7d 01 [2] 40 }

  condition:
    any of them
}