rule TTP_XOR_MULT_DOSStub_3f4e {
  strings:
    $key_3f4e = { 6b 26 [2] 1f 3e [2] 58 3c [2] 1f 2d [2] 51 21 [2] 5d 2b [2] 4a 20 [2] 51 6e [2] 6c }

  condition:
    any of them
}