rule TTP_XOR_MULT_DOSStub_253e {
  strings:
    $key_253e = { 71 56 [2] 05 4e [2] 42 4c [2] 05 5d [2] 4b 51 [2] 47 5b [2] 50 50 [2] 4b 1e [2] 76 }

  condition:
    any of them
}