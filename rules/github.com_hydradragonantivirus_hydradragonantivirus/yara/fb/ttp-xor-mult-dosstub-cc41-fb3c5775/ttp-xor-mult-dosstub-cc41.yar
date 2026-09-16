rule TTP_XOR_MULT_DOSStub_cc41 {
  strings:
    $key_cc41 = { 98 29 [2] ec 31 [2] ab 33 [2] ec 22 [2] a2 2e [2] ae 24 [2] b9 2f [2] a2 61 [2] 9f }

  condition:
    any of them
}