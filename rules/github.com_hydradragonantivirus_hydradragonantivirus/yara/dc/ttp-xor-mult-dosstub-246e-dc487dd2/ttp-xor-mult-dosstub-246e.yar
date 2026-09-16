rule TTP_XOR_MULT_DOSStub_246e {
  strings:
    $key_246e = { 70 06 [2] 04 1e [2] 43 1c [2] 04 0d [2] 4a 01 [2] 46 0b [2] 51 00 [2] 4a 4e [2] 77 }

  condition:
    any of them
}