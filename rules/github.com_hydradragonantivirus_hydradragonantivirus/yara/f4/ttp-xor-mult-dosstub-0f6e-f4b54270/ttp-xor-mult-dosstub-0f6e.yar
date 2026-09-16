rule TTP_XOR_MULT_DOSStub_0f6e {
  strings:
    $key_0f6e = { 5b 06 [2] 2f 1e [2] 68 1c [2] 2f 0d [2] 61 01 [2] 6d 0b [2] 7a 00 [2] 61 4e [2] 5c }

  condition:
    any of them
}