rule TTP_XOR_MULT_DOSStub_6b4e {
  strings:
    $key_6b4e = { 3f 26 [2] 4b 3e [2] 0c 3c [2] 4b 2d [2] 05 21 [2] 09 2b [2] 1e 20 [2] 05 6e [2] 38 }

  condition:
    any of them
}