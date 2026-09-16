rule TTP_XOR_MULT_DOSStub_2f30 {
  strings:
    $key_2f30 = { 7b 58 [2] 0f 40 [2] 48 42 [2] 0f 53 [2] 41 5f [2] 4d 55 [2] 5a 5e [2] 41 10 [2] 7c }

  condition:
    any of them
}