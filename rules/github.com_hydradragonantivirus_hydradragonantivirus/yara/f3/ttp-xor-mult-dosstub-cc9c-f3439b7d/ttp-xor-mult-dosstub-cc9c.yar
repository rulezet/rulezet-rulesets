rule TTP_XOR_MULT_DOSStub_cc9c {
  strings:
    $key_cc9c = { 98 f4 [2] ec ec [2] ab ee [2] ec ff [2] a2 f3 [2] ae f9 [2] b9 f2 [2] a2 bc [2] 9f }

  condition:
    any of them
}