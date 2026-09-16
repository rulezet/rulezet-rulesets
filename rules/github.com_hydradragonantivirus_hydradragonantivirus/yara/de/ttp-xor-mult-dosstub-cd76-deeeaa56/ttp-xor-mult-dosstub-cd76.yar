rule TTP_XOR_MULT_DOSStub_cd76 {
  strings:
    $key_cd76 = { 99 1e [2] ed 06 [2] aa 04 [2] ed 15 [2] a3 19 [2] af 13 [2] b8 18 [2] a3 56 [2] 9e }

  condition:
    any of them
}