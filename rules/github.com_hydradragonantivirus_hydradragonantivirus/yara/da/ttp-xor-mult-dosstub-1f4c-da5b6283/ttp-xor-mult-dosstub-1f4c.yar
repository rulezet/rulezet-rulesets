rule TTP_XOR_MULT_DOSStub_1f4c {
  strings:
    $key_1f4c = { 4b 24 [2] 3f 3c [2] 78 3e [2] 3f 2f [2] 71 23 [2] 7d 29 [2] 6a 22 [2] 71 6c [2] 4c }

  condition:
    any of them
}