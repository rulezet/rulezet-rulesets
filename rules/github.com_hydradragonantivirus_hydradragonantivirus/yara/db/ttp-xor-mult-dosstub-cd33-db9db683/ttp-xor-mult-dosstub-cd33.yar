rule TTP_XOR_MULT_DOSStub_cd33 {
  strings:
    $key_cd33 = { 99 5b [2] ed 43 [2] aa 41 [2] ed 50 [2] a3 5c [2] af 56 [2] b8 5d [2] a3 13 [2] 9e }

  condition:
    any of them
}