rule TTP_XOR_MULT_DOSStub_79e3 {
  strings:
    $key_79e3 = { 2d 8b [2] 59 93 [2] 1e 91 [2] 59 80 [2] 17 8c [2] 1b 86 [2] 0c 8d [2] 17 c3 [2] 2a }

  condition:
    any of them
}