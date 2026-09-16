rule TTP_XOR_MULT_DOSStub_cc69 {
  strings:
    $key_cc69 = { 98 01 [2] ec 19 [2] ab 1b [2] ec 0a [2] a2 06 [2] ae 0c [2] b9 07 [2] a2 49 [2] 9f }

  condition:
    any of them
}