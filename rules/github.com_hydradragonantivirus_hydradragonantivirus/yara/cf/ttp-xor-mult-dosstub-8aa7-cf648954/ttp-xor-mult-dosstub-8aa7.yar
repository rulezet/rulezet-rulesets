rule TTP_XOR_MULT_DOSStub_8aa7 {
  strings:
    $key_8aa7 = { de cf [2] aa d7 [2] ed d5 [2] aa c4 [2] e4 c8 [2] e8 c2 [2] ff c9 [2] e4 87 [2] d9 }

  condition:
    any of them
}