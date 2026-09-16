rule TTP_XOR_MULT_DOSStub_2321 {
  strings:
    $key_2321 = { 77 49 [2] 03 51 [2] 44 53 [2] 03 42 [2] 4d 4e [2] 41 44 [2] 56 4f [2] 4d 01 [2] 70 }

  condition:
    any of them
}