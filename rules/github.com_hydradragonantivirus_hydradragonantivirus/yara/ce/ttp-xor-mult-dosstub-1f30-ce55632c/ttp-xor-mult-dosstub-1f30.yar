rule TTP_XOR_MULT_DOSStub_1f30 {
  strings:
    $key_1f30 = { 4b 58 [2] 3f 40 [2] 78 42 [2] 3f 53 [2] 71 5f [2] 7d 55 [2] 6a 5e [2] 71 10 [2] 4c }

  condition:
    any of them
}