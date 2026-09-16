rule TTP_XOR_MULT_DOSStub_0d3e {
  strings:
    $key_0d3e = { 59 56 [2] 2d 4e [2] 6a 4c [2] 2d 5d [2] 63 51 [2] 6f 5b [2] 78 50 [2] 63 1e [2] 5e }

  condition:
    any of them
}