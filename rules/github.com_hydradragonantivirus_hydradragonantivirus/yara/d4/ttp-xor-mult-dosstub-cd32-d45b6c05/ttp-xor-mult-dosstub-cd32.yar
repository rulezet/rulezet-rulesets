rule TTP_XOR_MULT_DOSStub_cd32 {
  strings:
    $key_cd32 = { 99 5a [2] ed 42 [2] aa 40 [2] ed 51 [2] a3 5d [2] af 57 [2] b8 5c [2] a3 12 [2] 9e }

  condition:
    any of them
}