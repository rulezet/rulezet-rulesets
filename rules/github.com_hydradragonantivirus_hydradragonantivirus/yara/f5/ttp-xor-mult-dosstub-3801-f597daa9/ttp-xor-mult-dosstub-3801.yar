rule TTP_XOR_MULT_DOSStub_3801 {
  strings:
    $key_3801 = { 6c 69 [2] 18 71 [2] 5f 73 [2] 18 62 [2] 56 6e [2] 5a 64 [2] 4d 6f [2] 56 21 [2] 6b }

  condition:
    any of them
}