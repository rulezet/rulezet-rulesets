rule TTP_XOR_MULT_DOSStub_5021 {
  strings:
    $key_5021 = { 04 49 [2] 70 51 [2] 37 53 [2] 70 42 [2] 3e 4e [2] 32 44 [2] 25 4f [2] 3e 01 [2] 03 }

  condition:
    any of them
}