rule TTP_XOR_MULT_DOSStub_250e {
  strings:
    $key_250e = { 71 66 [2] 05 7e [2] 42 7c [2] 05 6d [2] 4b 61 [2] 47 6b [2] 50 60 [2] 4b 2e [2] 76 }

  condition:
    any of them
}