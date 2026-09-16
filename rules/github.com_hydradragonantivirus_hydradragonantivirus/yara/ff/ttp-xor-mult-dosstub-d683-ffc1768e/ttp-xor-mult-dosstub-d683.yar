rule TTP_XOR_MULT_DOSStub_d683 {
  strings:
    $key_d683 = { 82 eb [2] f6 f3 [2] b1 f1 [2] f6 e0 [2] b8 ec [2] b4 e6 [2] a3 ed [2] b8 a3 [2] 85 }

  condition:
    any of them
}