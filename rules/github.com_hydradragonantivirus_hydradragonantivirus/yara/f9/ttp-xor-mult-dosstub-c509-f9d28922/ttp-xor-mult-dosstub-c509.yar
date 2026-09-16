rule TTP_XOR_MULT_DOSStub_c509 {
  strings:
    $key_c509 = { 91 61 [2] e5 79 [2] a2 7b [2] e5 6a [2] ab 66 [2] a7 6c [2] b0 67 [2] ab 29 [2] 96 }

  condition:
    any of them
}