rule TTP_XOR_MULT_DOSStub_c562 {
  strings:
    $key_c562 = { 91 0a [2] e5 12 [2] a2 10 [2] e5 01 [2] ab 0d [2] a7 07 [2] b0 0c [2] ab 42 [2] 96 }

  condition:
    any of them
}