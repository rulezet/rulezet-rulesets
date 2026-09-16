rule TTP_XOR_MULT_DOSStub_3821 {
  strings:
    $key_3821 = { 6c 49 [2] 18 51 [2] 5f 53 [2] 18 42 [2] 56 4e [2] 5a 44 [2] 4d 4f [2] 56 01 [2] 6b }

  condition:
    any of them
}