rule TTP_XOR_MULT_DOSStub_084c {
  strings:
    $key_084c = { 5c 24 [2] 28 3c [2] 6f 3e [2] 28 2f [2] 66 23 [2] 6a 29 [2] 7d 22 [2] 66 6c [2] 5b }

  condition:
    any of them
}