rule TTP_XOR_MULT_DOSStub_6321 {
  strings:
    $key_6321 = { 37 49 [2] 43 51 [2] 04 53 [2] 43 42 [2] 0d 4e [2] 01 44 [2] 16 4f [2] 0d 01 [2] 30 }

  condition:
    any of them
}