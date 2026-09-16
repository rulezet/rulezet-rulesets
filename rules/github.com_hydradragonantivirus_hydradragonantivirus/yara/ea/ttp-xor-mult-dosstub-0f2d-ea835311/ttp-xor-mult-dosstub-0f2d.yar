rule TTP_XOR_MULT_DOSStub_0f2d {
  strings:
    $key_0f2d = { 5b 45 [2] 2f 5d [2] 68 5f [2] 2f 4e [2] 61 42 [2] 6d 48 [2] 7a 43 [2] 61 0d [2] 5c }

  condition:
    any of them
}