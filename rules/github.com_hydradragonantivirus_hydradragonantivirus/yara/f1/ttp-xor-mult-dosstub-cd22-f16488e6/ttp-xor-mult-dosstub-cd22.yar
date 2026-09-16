rule TTP_XOR_MULT_DOSStub_cd22 {
  strings:
    $key_cd22 = { 99 4a [2] ed 52 [2] aa 50 [2] ed 41 [2] a3 4d [2] af 47 [2] b8 4c [2] a3 02 [2] 9e }

  condition:
    any of them
}