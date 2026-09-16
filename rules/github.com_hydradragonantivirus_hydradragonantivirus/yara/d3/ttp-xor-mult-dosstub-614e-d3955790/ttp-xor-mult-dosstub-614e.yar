rule TTP_XOR_MULT_DOSStub_614e {
  strings:
    $key_614e = { 35 26 [2] 41 3e [2] 06 3c [2] 41 2d [2] 0f 21 [2] 03 2b [2] 14 20 [2] 0f 6e [2] 32 }

  condition:
    any of them
}