rule TTP_XOR_MULT_DOSStub_c56e {
  strings:
    $key_c56e = { 91 06 [2] e5 1e [2] a2 1c [2] e5 0d [2] ab 01 [2] a7 0b [2] b0 00 [2] ab 4e [2] 96 }

  condition:
    any of them
}