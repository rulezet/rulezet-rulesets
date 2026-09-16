rule TTP_XOR_MULT_DOSStub_cc4e {
  strings:
    $key_cc4e = { 98 26 [2] ec 3e [2] ab 3c [2] ec 2d [2] a2 21 [2] ae 2b [2] b9 20 [2] a2 6e [2] 9f }

  condition:
    any of them
}