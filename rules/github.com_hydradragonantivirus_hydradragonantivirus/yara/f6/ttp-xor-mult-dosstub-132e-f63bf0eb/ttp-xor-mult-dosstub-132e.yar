rule TTP_XOR_MULT_DOSStub_132e {
  strings:
    $key_132e = { 47 46 [2] 33 5e [2] 74 5c [2] 33 4d [2] 7d 41 [2] 71 4b [2] 66 40 [2] 7d 0e [2] 40 }

  condition:
    any of them
}