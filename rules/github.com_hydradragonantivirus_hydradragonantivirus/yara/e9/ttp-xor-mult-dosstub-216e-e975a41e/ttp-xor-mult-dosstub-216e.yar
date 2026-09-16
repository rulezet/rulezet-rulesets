rule TTP_XOR_MULT_DOSStub_216e {
  strings:
    $key_216e = { 75 06 [2] 01 1e [2] 46 1c [2] 01 0d [2] 4f 01 [2] 43 0b [2] 54 00 [2] 4f 4e [2] 72 }

  condition:
    any of them
}