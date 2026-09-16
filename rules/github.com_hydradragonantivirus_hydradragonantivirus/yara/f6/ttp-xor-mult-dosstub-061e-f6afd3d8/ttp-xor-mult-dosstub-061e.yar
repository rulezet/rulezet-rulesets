rule TTP_XOR_MULT_DOSStub_061e {
  strings:
    $key_061e = { 52 76 [2] 26 6e [2] 61 6c [2] 26 7d [2] 68 71 [2] 64 7b [2] 73 70 [2] 68 3e [2] 55 }

  condition:
    any of them
}