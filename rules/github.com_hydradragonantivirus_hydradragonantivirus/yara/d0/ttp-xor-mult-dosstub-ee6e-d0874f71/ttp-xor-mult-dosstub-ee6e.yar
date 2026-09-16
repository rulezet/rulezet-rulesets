rule TTP_XOR_MULT_DOSStub_ee6e {
  strings:
    $key_ee6e = { ba 06 [2] ce 1e [2] 89 1c [2] ce 0d [2] 80 01 [2] 8c 0b [2] 9b 00 [2] 80 4e [2] bd }

  condition:
    any of them
}