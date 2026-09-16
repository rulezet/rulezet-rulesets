rule TTP_XOR_MULT_DOSStub_6e0e {
  strings:
    $key_6e0e = { 3a 66 [2] 4e 7e [2] 09 7c [2] 4e 6d [2] 00 61 [2] 0c 6b [2] 1b 60 [2] 00 2e [2] 3d }

  condition:
    any of them
}