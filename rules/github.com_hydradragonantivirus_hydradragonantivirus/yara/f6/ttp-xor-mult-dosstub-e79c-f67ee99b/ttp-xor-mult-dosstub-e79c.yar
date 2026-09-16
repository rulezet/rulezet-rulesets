rule TTP_XOR_MULT_DOSStub_e79c {
  strings:
    $key_e79c = { b3 f4 [2] c7 ec [2] 80 ee [2] c7 ff [2] 89 f3 [2] 85 f9 [2] 92 f2 [2] 89 bc [2] b4 }

  condition:
    any of them
}