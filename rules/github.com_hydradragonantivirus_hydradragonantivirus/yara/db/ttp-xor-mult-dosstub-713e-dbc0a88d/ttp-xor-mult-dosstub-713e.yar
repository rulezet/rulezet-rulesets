rule TTP_XOR_MULT_DOSStub_713e {
  strings:
    $key_713e = { 25 56 [2] 51 4e [2] 16 4c [2] 51 5d [2] 1f 51 [2] 13 5b [2] 04 50 [2] 1f 1e [2] 22 }

  condition:
    any of them
}