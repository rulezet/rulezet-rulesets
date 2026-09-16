rule TTP_XOR_MULT_DOSStub_cc1b {
  strings:
    $key_cc1b = { 98 73 [2] ec 6b [2] ab 69 [2] ec 78 [2] a2 74 [2] ae 7e [2] b9 75 [2] a2 3b [2] 9f }

  condition:
    any of them
}