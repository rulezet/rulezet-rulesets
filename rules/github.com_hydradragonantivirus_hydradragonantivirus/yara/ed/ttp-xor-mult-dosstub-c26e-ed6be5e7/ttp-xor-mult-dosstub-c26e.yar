rule TTP_XOR_MULT_DOSStub_c26e {
  strings:
    $key_c26e = { 96 06 [2] e2 1e [2] a5 1c [2] e2 0d [2] ac 01 [2] a0 0b [2] b7 00 [2] ac 4e [2] 91 }

  condition:
    any of them
}