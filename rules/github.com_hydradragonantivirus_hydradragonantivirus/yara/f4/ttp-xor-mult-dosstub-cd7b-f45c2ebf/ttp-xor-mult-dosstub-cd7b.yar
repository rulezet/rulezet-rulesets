rule TTP_XOR_MULT_DOSStub_cd7b {
  strings:
    $key_cd7b = { 99 13 [2] ed 0b [2] aa 09 [2] ed 18 [2] a3 14 [2] af 1e [2] b8 15 [2] a3 5b [2] 9e }

  condition:
    any of them
}