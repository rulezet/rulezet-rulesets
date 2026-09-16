rule TTP_XOR_MULT_DOSStub_cd1a {
  strings:
    $key_cd1a = { 99 72 [2] ed 6a [2] aa 68 [2] ed 79 [2] a3 75 [2] af 7f [2] b8 74 [2] a3 3a [2] 9e }

  condition:
    any of them
}