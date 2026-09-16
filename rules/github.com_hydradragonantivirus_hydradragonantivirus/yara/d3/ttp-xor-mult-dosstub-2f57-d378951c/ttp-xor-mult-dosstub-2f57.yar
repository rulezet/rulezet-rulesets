rule TTP_XOR_MULT_DOSStub_2f57 {
  strings:
    $key_2f57 = { 7b 3f [2] 0f 27 [2] 48 25 [2] 0f 34 [2] 41 38 [2] 4d 32 [2] 5a 39 [2] 41 77 [2] 7c }

  condition:
    any of them
}