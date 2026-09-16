rule TTP_XOR_MULT_DOSStub_517e {
  strings:
    $key_517e = { 05 16 [2] 71 0e [2] 36 0c [2] 71 1d [2] 3f 11 [2] 33 1b [2] 24 10 [2] 3f 5e [2] 02 }

  condition:
    any of them
}