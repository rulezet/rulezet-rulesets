rule TTP_XOR_MULT_DOSStub_cd5b {
  strings:
    $key_cd5b = { 99 33 [2] ed 2b [2] aa 29 [2] ed 38 [2] a3 34 [2] af 3e [2] b8 35 [2] a3 7b [2] 9e }

  condition:
    any of them
}