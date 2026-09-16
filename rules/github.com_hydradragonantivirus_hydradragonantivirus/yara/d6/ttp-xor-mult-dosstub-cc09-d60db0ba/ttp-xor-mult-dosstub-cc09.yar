rule TTP_XOR_MULT_DOSStub_cc09 {
  strings:
    $key_cc09 = { 98 61 [2] ec 79 [2] ab 7b [2] ec 6a [2] a2 66 [2] ae 6c [2] b9 67 [2] a2 29 [2] 9f }

  condition:
    any of them
}