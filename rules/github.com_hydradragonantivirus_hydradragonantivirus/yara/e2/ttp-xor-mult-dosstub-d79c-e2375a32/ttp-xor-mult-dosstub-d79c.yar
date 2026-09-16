rule TTP_XOR_MULT_DOSStub_d79c {
  strings:
    $key_d79c = { 83 f4 [2] f7 ec [2] b0 ee [2] f7 ff [2] b9 f3 [2] b5 f9 [2] a2 f2 [2] b9 bc [2] 84 }

  condition:
    any of them
}