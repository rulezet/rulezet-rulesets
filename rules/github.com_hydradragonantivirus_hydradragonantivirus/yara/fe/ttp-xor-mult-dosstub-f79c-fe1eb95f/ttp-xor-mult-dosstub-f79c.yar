rule TTP_XOR_MULT_DOSStub_f79c {
  strings:
    $key_f79c = { a3 f4 [2] d7 ec [2] 90 ee [2] d7 ff [2] 99 f3 [2] 95 f9 [2] 82 f2 [2] 99 bc [2] a4 }

  condition:
    any of them
}