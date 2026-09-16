rule TTP_XOR_MULT_DOSStub_6e3e {
  strings:
    $key_6e3e = { 3a 56 [2] 4e 4e [2] 09 4c [2] 4e 5d [2] 00 51 [2] 0c 5b [2] 1b 50 [2] 00 1e [2] 3d }

  condition:
    any of them
}