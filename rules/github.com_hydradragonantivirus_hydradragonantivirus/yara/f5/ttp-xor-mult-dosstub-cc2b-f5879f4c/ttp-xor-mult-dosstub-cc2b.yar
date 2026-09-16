rule TTP_XOR_MULT_DOSStub_cc2b {
  strings:
    $key_cc2b = { 98 43 [2] ec 5b [2] ab 59 [2] ec 48 [2] a2 44 [2] ae 4e [2] b9 45 [2] a2 0b [2] 9f }

  condition:
    any of them
}