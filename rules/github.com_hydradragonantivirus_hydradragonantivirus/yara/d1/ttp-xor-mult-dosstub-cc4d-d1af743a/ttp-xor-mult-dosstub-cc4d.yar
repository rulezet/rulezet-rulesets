rule TTP_XOR_MULT_DOSStub_cc4d {
  strings:
    $key_cc4d = { 98 25 [2] ec 3d [2] ab 3f [2] ec 2e [2] a2 22 [2] ae 28 [2] b9 23 [2] a2 6d [2] 9f }

  condition:
    any of them
}