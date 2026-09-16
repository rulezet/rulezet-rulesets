rule TTP_XOR_MULT_DOSStub_cde8 {
  strings:
    $key_cde8 = { 99 80 [2] ed 98 [2] aa 9a [2] ed 8b [2] a3 87 [2] af 8d [2] b8 86 [2] a3 c8 [2] 9e }

  condition:
    any of them
}