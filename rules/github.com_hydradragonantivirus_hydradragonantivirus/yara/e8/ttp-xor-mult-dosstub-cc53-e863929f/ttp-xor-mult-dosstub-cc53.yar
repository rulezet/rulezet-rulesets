rule TTP_XOR_MULT_DOSStub_cc53 {
  strings:
    $key_cc53 = { 98 3b [2] ec 23 [2] ab 21 [2] ec 30 [2] a2 3c [2] ae 36 [2] b9 3d [2] a2 73 [2] 9f }

  condition:
    any of them
}