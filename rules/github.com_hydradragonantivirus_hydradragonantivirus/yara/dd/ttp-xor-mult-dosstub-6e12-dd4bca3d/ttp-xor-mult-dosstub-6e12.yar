rule TTP_XOR_MULT_DOSStub_6e12 {
  strings:
    $key_6e12 = { 3a 7a [2] 4e 62 [2] 09 60 [2] 4e 71 [2] 00 7d [2] 0c 77 [2] 1b 7c [2] 00 32 [2] 3d }

  condition:
    any of them
}