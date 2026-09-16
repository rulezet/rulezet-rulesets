rule TTP_XOR_MULT_DOSStub_721e {
  strings:
    $key_721e = { 26 76 [2] 52 6e [2] 15 6c [2] 52 7d [2] 1c 71 [2] 10 7b [2] 07 70 [2] 1c 3e [2] 21 }

  condition:
    any of them
}