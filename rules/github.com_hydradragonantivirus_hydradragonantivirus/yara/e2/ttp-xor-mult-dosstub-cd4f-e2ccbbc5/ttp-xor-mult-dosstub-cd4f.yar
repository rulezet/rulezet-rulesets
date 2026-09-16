rule TTP_XOR_MULT_DOSStub_cd4f {
  strings:
    $key_cd4f = { 99 27 [2] ed 3f [2] aa 3d [2] ed 2c [2] a3 20 [2] af 2a [2] b8 21 [2] a3 6f [2] 9e }

  condition:
    any of them
}