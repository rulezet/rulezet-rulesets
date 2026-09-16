rule TTP_XOR_MULT_DOSStub_c51e {
  strings:
    $key_c51e = { 91 76 [2] e5 6e [2] a2 6c [2] e5 7d [2] ab 71 [2] a7 7b [2] b0 70 [2] ab 3e [2] 96 }

  condition:
    any of them
}