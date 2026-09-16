rule TTP_XOR_MULT_DOSStub_072e {
  strings:
    $key_072e = { 53 46 [2] 27 5e [2] 60 5c [2] 27 4d [2] 69 41 [2] 65 4b [2] 72 40 [2] 69 0e [2] 54 }

  condition:
    any of them
}