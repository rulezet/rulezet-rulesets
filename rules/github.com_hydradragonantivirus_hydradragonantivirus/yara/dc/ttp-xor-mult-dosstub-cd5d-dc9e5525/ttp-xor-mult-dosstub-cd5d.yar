rule TTP_XOR_MULT_DOSStub_cd5d {
  strings:
    $key_cd5d = { 99 35 [2] ed 2d [2] aa 2f [2] ed 3e [2] a3 32 [2] af 38 [2] b8 33 [2] a3 7d [2] 9e }

  condition:
    any of them
}