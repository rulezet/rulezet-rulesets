rule TTP_XOR_MULT_DOSStub_181e {
  strings:
    $key_181e = { 4c 76 [2] 38 6e [2] 7f 6c [2] 38 7d [2] 76 71 [2] 7a 7b [2] 6d 70 [2] 76 3e [2] 4b }

  condition:
    any of them
}