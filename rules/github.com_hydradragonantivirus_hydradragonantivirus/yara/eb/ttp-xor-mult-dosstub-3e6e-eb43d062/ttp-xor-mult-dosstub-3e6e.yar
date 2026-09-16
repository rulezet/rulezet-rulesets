rule TTP_XOR_MULT_DOSStub_3e6e {
  strings:
    $key_3e6e = { 6a 06 [2] 1e 1e [2] 59 1c [2] 1e 0d [2] 50 01 [2] 5c 0b [2] 4b 00 [2] 50 4e [2] 6d }

  condition:
    any of them
}