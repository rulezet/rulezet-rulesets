rule TTP_XOR_MULT_DOSStub_0f21 {
  strings:
    $key_0f21 = { 5b 49 [2] 2f 51 [2] 68 53 [2] 2f 42 [2] 61 4e [2] 6d 44 [2] 7a 4f [2] 61 01 [2] 5c }

  condition:
    any of them
}