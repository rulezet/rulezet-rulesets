rule TTP_XOR_MULT_DOSStub_5f1e {
  strings:
    $key_5f1e = { 0b 76 [2] 7f 6e [2] 38 6c [2] 7f 7d [2] 31 71 [2] 3d 7b [2] 2a 70 [2] 31 3e [2] 0c }

  condition:
    any of them
}