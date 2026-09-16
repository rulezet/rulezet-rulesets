rule TTP_XOR_MULT_DOSStub_cc08 {
  strings:
    $key_cc08 = { 98 60 [2] ec 78 [2] ab 7a [2] ec 6b [2] a2 67 [2] ae 6d [2] b9 66 [2] a2 28 [2] 9f }

  condition:
    any of them
}