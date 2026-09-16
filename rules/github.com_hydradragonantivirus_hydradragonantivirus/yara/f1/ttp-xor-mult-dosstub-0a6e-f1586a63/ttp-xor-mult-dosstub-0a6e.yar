rule TTP_XOR_MULT_DOSStub_0a6e {
  strings:
    $key_0a6e = { 5e 06 [2] 2a 1e [2] 6d 1c [2] 2a 0d [2] 64 01 [2] 68 0b [2] 7f 00 [2] 64 4e [2] 59 }

  condition:
    any of them
}