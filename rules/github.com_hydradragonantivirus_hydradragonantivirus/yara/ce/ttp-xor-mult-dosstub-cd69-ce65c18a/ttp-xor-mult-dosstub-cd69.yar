rule TTP_XOR_MULT_DOSStub_cd69 {
  strings:
    $key_cd69 = { 99 01 [2] ed 19 [2] aa 1b [2] ed 0a [2] a3 06 [2] af 0c [2] b8 07 [2] a3 49 [2] 9e }

  condition:
    any of them
}