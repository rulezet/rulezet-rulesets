rule TTP_XOR_MULT_DOSStub_cc9d {
  strings:
    $key_cc9d = { 98 f5 [2] ec ed [2] ab ef [2] ec fe [2] a2 f2 [2] ae f8 [2] b9 f3 [2] a2 bd [2] 9f }

  condition:
    any of them
}