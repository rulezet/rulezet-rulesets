rule TTP_XOR_MULT_DOSStub_cce7 {
  strings:
    $key_cce7 = { 98 8f [2] ec 97 [2] ab 95 [2] ec 84 [2] a2 88 [2] ae 82 [2] b9 89 [2] a2 c7 [2] 9f }

  condition:
    any of them
}