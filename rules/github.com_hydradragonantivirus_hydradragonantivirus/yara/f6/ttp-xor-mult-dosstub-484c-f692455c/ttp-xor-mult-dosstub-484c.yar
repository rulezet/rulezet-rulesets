rule TTP_XOR_MULT_DOSStub_484c {
  strings:
    $key_484c = { 1c 24 [2] 68 3c [2] 2f 3e [2] 68 2f [2] 26 23 [2] 2a 29 [2] 3d 22 [2] 26 6c [2] 1b }

  condition:
    any of them
}