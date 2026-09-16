rule TTP_XOR_MULT_DOSStub_2f26 {
  strings:
    $key_2f26 = { 7b 4e [2] 0f 56 [2] 48 54 [2] 0f 45 [2] 41 49 [2] 4d 43 [2] 5a 48 [2] 41 06 [2] 7c }

  condition:
    any of them
}