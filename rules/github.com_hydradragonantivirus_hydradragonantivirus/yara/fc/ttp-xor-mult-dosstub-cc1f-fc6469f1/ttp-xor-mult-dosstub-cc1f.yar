rule TTP_XOR_MULT_DOSStub_cc1f {
  strings:
    $key_cc1f = { 98 77 [2] ec 6f [2] ab 6d [2] ec 7c [2] a2 70 [2] ae 7a [2] b9 71 [2] a2 3f [2] 9f }

  condition:
    any of them
}