rule TTP_XOR_MULT_DOSStub_c569 {
  strings:
    $key_c569 = { 91 01 [2] e5 19 [2] a2 1b [2] e5 0a [2] ab 06 [2] a7 0c [2] b0 07 [2] ab 49 [2] 96 }

  condition:
    any of them
}