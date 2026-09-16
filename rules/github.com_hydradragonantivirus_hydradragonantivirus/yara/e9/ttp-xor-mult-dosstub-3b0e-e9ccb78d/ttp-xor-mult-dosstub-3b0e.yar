rule TTP_XOR_MULT_DOSStub_3b0e {
  strings:
    $key_3b0e = { 6f 66 [2] 1b 7e [2] 5c 7c [2] 1b 6d [2] 55 61 [2] 59 6b [2] 4e 60 [2] 55 2e [2] 68 }

  condition:
    any of them
}