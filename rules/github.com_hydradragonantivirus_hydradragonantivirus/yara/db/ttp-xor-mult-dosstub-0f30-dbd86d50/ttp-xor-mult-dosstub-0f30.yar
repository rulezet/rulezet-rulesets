rule TTP_XOR_MULT_DOSStub_0f30 {
  strings:
    $key_0f30 = { 5b 58 [2] 2f 40 [2] 68 42 [2] 2f 53 [2] 61 5f [2] 6d 55 [2] 7a 5e [2] 61 10 [2] 5c }

  condition:
    any of them
}