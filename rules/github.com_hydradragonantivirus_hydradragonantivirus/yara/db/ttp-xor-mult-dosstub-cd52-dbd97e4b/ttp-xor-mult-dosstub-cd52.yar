rule TTP_XOR_MULT_DOSStub_cd52 {
  strings:
    $key_cd52 = { 99 3a [2] ed 22 [2] aa 20 [2] ed 31 [2] a3 3d [2] af 37 [2] b8 3c [2] a3 72 [2] 9e }

  condition:
    any of them
}