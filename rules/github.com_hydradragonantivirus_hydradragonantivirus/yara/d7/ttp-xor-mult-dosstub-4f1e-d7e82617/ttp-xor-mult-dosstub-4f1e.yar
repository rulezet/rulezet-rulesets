rule TTP_XOR_MULT_DOSStub_4f1e {
  strings:
    $key_4f1e = { 1b 76 [2] 6f 6e [2] 28 6c [2] 6f 7d [2] 21 71 [2] 2d 7b [2] 3a 70 [2] 21 3e [2] 1c }

  condition:
    any of them
}