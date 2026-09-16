rule TTP_XOR_MULT_DOSStub_e339 {
  strings:
    $key_e339 = { b7 51 [2] c3 49 [2] 84 4b [2] c3 5a [2] 8d 56 [2] 81 5c [2] 96 57 [2] 8d 19 [2] b0 }

  condition:
    any of them
}