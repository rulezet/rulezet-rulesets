rule TTP_XOR_MULT_DOSStub_1f4e {
  strings:
    $key_1f4e = { 4b 26 [2] 3f 3e [2] 78 3c [2] 3f 2d [2] 71 21 [2] 7d 2b [2] 6a 20 [2] 71 6e [2] 4c }

  condition:
    any of them
}