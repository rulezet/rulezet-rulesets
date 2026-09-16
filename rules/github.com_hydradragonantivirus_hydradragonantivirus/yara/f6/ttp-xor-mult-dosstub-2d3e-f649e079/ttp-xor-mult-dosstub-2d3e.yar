rule TTP_XOR_MULT_DOSStub_2d3e {
  strings:
    $key_2d3e = { 79 56 [2] 0d 4e [2] 4a 4c [2] 0d 5d [2] 43 51 [2] 4f 5b [2] 58 50 [2] 43 1e [2] 7e }

  condition:
    any of them
}