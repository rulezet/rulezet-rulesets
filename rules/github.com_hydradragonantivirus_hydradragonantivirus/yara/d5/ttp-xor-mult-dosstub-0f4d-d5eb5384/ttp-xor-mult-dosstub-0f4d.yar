rule TTP_XOR_MULT_DOSStub_0f4d {
  strings:
    $key_0f4d = { 5b 25 [2] 2f 3d [2] 68 3f [2] 2f 2e [2] 61 22 [2] 6d 28 [2] 7a 23 [2] 61 6d [2] 5c }

  condition:
    any of them
}