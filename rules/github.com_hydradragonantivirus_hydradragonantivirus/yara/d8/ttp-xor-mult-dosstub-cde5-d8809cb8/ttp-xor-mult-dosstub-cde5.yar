rule TTP_XOR_MULT_DOSStub_cde5 {
  strings:
    $key_cde5 = { 99 8d [2] ed 95 [2] aa 97 [2] ed 86 [2] a3 8a [2] af 80 [2] b8 8b [2] a3 c5 [2] 9e }

  condition:
    any of them
}