rule TTP_XOR_MULT_DOSStub_1ad3 {
  strings:
    $key_1ad3 = { 4e bb [2] 3a a3 [2] 7d a1 [2] 3a b0 [2] 74 bc [2] 78 b6 [2] 6f bd [2] 74 f3 [2] 49 }

  condition:
    any of them
}