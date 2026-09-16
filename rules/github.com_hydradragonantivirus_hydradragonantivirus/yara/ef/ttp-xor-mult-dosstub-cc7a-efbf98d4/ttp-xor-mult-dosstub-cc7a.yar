rule TTP_XOR_MULT_DOSStub_cc7a {
  strings:
    $key_cc7a = { 98 12 [2] ec 0a [2] ab 08 [2] ec 19 [2] a2 15 [2] ae 1f [2] b9 14 [2] a2 5a [2] 9f }

  condition:
    any of them
}