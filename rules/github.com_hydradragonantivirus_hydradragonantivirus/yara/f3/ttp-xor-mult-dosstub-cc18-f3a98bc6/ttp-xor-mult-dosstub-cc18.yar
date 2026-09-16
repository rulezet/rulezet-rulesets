rule TTP_XOR_MULT_DOSStub_cc18 {
  strings:
    $key_cc18 = { 98 70 [2] ec 68 [2] ab 6a [2] ec 7b [2] a2 77 [2] ae 7d [2] b9 76 [2] a2 38 [2] 9f }

  condition:
    any of them
}