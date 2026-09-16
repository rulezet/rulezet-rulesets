rule TTP_XOR_MULT_DOSStub_281e {
  strings:
    $key_281e = { 7c 76 [2] 08 6e [2] 4f 6c [2] 08 7d [2] 46 71 [2] 4a 7b [2] 5d 70 [2] 46 3e [2] 7b }

  condition:
    any of them
}