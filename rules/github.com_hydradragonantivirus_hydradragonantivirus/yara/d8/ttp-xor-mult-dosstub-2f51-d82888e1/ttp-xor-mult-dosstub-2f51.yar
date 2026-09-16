rule TTP_XOR_MULT_DOSStub_2f51 {
  strings:
    $key_2f51 = { 7b 39 [2] 0f 21 [2] 48 23 [2] 0f 32 [2] 41 3e [2] 4d 34 [2] 5a 3f [2] 41 71 [2] 7c }

  condition:
    any of them
}