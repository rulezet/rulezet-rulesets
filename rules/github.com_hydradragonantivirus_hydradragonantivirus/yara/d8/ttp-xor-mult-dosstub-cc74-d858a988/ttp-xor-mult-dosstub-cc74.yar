rule TTP_XOR_MULT_DOSStub_cc74 {
  strings:
    $key_cc74 = { 98 1c [2] ec 04 [2] ab 06 [2] ec 17 [2] a2 1b [2] ae 11 [2] b9 1a [2] a2 54 [2] 9f }

  condition:
    any of them
}