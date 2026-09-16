rule TTP_XOR_MULT_DOSStub_260e {
  strings:
    $key_260e = { 72 66 [2] 06 7e [2] 41 7c [2] 06 6d [2] 48 61 [2] 44 6b [2] 53 60 [2] 48 2e [2] 75 }

  condition:
    any of them
}