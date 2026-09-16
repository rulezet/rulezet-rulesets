rule TTP_XOR_MULT_DOSStub_cc38 {
  strings:
    $key_cc38 = { 98 50 [2] ec 48 [2] ab 4a [2] ec 5b [2] a2 57 [2] ae 5d [2] b9 56 [2] a2 18 [2] 9f }

  condition:
    any of them
}