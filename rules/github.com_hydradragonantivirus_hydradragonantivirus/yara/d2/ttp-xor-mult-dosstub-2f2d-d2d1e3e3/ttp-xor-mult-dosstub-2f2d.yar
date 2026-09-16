rule TTP_XOR_MULT_DOSStub_2f2d {
  strings:
    $key_2f2d = { 7b 45 [2] 0f 5d [2] 48 5f [2] 0f 4e [2] 41 42 [2] 4d 48 [2] 5a 43 [2] 41 0d [2] 7c }

  condition:
    any of them
}