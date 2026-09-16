rule TTP_XOR_MULT_DOSStub_cd19 {
  strings:
    $key_cd19 = { 99 71 [2] ed 69 [2] aa 6b [2] ed 7a [2] a3 76 [2] af 7c [2] b8 77 [2] a3 39 [2] 9e }

  condition:
    any of them
}