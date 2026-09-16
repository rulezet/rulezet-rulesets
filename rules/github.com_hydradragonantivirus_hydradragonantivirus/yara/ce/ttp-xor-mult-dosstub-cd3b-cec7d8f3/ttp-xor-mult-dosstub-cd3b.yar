rule TTP_XOR_MULT_DOSStub_cd3b {
  strings:
    $key_cd3b = { 99 53 [2] ed 4b [2] aa 49 [2] ed 58 [2] a3 54 [2] af 5e [2] b8 55 [2] a3 1b [2] 9e }

  condition:
    any of them
}