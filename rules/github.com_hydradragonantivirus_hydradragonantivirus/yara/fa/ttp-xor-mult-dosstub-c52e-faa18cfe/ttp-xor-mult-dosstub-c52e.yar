rule TTP_XOR_MULT_DOSStub_c52e {
  strings:
    $key_c52e = { 91 46 [2] e5 5e [2] a2 5c [2] e5 4d [2] ab 41 [2] a7 4b [2] b0 40 [2] ab 0e [2] 96 }

  condition:
    any of them
}