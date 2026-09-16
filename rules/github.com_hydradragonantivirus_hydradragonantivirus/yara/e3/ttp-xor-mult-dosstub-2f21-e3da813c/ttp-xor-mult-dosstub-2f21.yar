rule TTP_XOR_MULT_DOSStub_2f21 {
  strings:
    $key_2f21 = { 7b 49 [2] 0f 51 [2] 48 53 [2] 0f 42 [2] 41 4e [2] 4d 44 [2] 5a 4f [2] 41 01 [2] 7c }

  condition:
    any of them
}