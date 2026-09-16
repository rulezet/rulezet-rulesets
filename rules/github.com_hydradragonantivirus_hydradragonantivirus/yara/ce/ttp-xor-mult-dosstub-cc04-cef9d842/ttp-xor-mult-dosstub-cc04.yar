rule TTP_XOR_MULT_DOSStub_cc04 {
  strings:
    $key_cc04 = { 98 6c [2] ec 74 [2] ab 76 [2] ec 67 [2] a2 6b [2] ae 61 [2] b9 6a [2] a2 24 [2] 9f }

  condition:
    any of them
}