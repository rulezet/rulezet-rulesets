rule TTP_XOR_MULT_DOSStub_0a1e {
  strings:
    $key_0a1e = { 5e 76 [2] 2a 6e [2] 6d 6c [2] 2a 7d [2] 64 71 [2] 68 7b [2] 7f 70 [2] 64 3e [2] 59 }

  condition:
    any of them
}