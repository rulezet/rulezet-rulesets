rule TTP_XOR_MULT_DOSStub_cd14 {
  strings:
    $key_cd14 = { 99 7c [2] ed 64 [2] aa 66 [2] ed 77 [2] a3 7b [2] af 71 [2] b8 7a [2] a3 34 [2] 9e }

  condition:
    any of them
}