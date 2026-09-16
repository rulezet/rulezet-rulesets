rule TTP_XOR_MULT_DOSStub_6d3e {
  strings:
    $key_6d3e = { 39 56 [2] 4d 4e [2] 0a 4c [2] 4d 5d [2] 03 51 [2] 0f 5b [2] 18 50 [2] 03 1e [2] 3e }

  condition:
    any of them
}