rule TTP_XOR_MULT_DOSStub_cc32 {
  strings:
    $key_cc32 = { 98 5a [2] ec 42 [2] ab 40 [2] ec 51 [2] a2 5d [2] ae 57 [2] b9 5c [2] a2 12 [2] 9f }

  condition:
    any of them
}