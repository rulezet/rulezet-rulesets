rule TTP_XOR_MULT_DOSStub_386e {
  strings:
    $key_386e = { 6c 06 [2] 18 1e [2] 5f 1c [2] 18 0d [2] 56 01 [2] 5a 0b [2] 4d 00 [2] 56 4e [2] 6b }

  condition:
    any of them
}