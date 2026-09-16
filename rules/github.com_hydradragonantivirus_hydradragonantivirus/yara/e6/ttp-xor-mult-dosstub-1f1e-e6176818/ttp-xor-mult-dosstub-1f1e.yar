rule TTP_XOR_MULT_DOSStub_1f1e {
  strings:
    $key_1f1e = { 4b 76 [2] 3f 6e [2] 78 6c [2] 3f 7d [2] 71 71 [2] 7d 7b [2] 6a 70 [2] 71 3e [2] 4c }

  condition:
    any of them
}