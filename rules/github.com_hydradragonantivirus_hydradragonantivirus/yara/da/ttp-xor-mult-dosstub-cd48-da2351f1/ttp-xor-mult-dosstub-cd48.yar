rule TTP_XOR_MULT_DOSStub_cd48 {
  strings:
    $key_cd48 = { 99 20 [2] ed 38 [2] aa 3a [2] ed 2b [2] a3 27 [2] af 2d [2] b8 26 [2] a3 68 [2] 9e }

  condition:
    any of them
}