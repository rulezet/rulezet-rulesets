rule TTP_XOR_MULT_DOSStub_cd07 {
  strings:
    $key_cd07 = { 99 6f [2] ed 77 [2] aa 75 [2] ed 64 [2] a3 68 [2] af 62 [2] b8 69 [2] a3 27 [2] 9e }

  condition:
    any of them
}