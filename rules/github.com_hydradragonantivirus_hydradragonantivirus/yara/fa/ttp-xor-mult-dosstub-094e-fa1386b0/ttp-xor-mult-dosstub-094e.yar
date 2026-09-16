rule TTP_XOR_MULT_DOSStub_094e {
  strings:
    $key_094e = { 5d 26 [2] 29 3e [2] 6e 3c [2] 29 2d [2] 67 21 [2] 6b 2b [2] 7c 20 [2] 67 6e [2] 5a }

  condition:
    any of them
}