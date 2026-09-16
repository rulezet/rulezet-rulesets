rule TTP_XOR_MULT_DOSStub_cd79 {
  strings:
    $key_cd79 = { 99 11 [2] ed 09 [2] aa 0b [2] ed 1a [2] a3 16 [2] af 1c [2] b8 17 [2] a3 59 [2] 9e }

  condition:
    any of them
}