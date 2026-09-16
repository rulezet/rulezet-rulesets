rule TTP_XOR_MULT_DOSStub_5b6e {
  strings:
    $key_5b6e = { 0f 06 [2] 7b 1e [2] 3c 1c [2] 7b 0d [2] 35 01 [2] 39 0b [2] 2e 00 [2] 35 4e [2] 08 }

  condition:
    any of them
}