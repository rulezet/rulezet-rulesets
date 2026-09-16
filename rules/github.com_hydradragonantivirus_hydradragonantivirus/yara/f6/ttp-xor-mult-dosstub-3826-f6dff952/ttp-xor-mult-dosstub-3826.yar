rule TTP_XOR_MULT_DOSStub_3826 {
  strings:
    $key_3826 = { 6c 4e [2] 18 56 [2] 5f 54 [2] 18 45 [2] 56 49 [2] 5a 43 [2] 4d 48 [2] 56 06 [2] 6b }

  condition:
    any of them
}