rule TTP_XOR_MULT_DOSStub_790e {
  strings:
    $key_790e = { 2d 66 [2] 59 7e [2] 1e 7c [2] 59 6d [2] 17 61 [2] 1b 6b [2] 0c 60 [2] 17 2e [2] 2a }

  condition:
    any of them
}