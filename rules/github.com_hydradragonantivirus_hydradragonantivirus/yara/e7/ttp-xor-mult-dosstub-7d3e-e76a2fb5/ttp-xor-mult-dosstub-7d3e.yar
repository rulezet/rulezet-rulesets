rule TTP_XOR_MULT_DOSStub_7d3e {
  strings:
    $key_7d3e = { 29 56 [2] 5d 4e [2] 1a 4c [2] 5d 5d [2] 13 51 [2] 1f 5b [2] 08 50 [2] 13 1e [2] 2e }

  condition:
    any of them
}