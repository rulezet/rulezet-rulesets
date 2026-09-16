rule TTP_XOR_MULT_DOSStub_2f4d {
  strings:
    $key_2f4d = { 7b 25 [2] 0f 3d [2] 48 3f [2] 0f 2e [2] 41 22 [2] 4d 28 [2] 5a 23 [2] 41 6d [2] 7c }

  condition:
    any of them
}