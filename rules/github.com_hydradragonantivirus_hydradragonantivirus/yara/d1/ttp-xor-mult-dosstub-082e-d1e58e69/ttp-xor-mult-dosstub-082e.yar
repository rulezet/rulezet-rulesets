rule TTP_XOR_MULT_DOSStub_082e {
  strings:
    $key_082e = { 5c 46 [2] 28 5e [2] 6f 5c [2] 28 4d [2] 66 41 [2] 6a 4b [2] 7d 40 [2] 66 0e [2] 5b }

  condition:
    any of them
}