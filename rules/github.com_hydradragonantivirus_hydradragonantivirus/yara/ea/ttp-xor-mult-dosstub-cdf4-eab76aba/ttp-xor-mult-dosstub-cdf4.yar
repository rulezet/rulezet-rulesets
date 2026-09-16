rule TTP_XOR_MULT_DOSStub_cdf4 {
  strings:
    $key_cdf4 = { 99 9c [2] ed 84 [2] aa 86 [2] ed 97 [2] a3 9b [2] af 91 [2] b8 9a [2] a3 d4 [2] 9e }

  condition:
    any of them
}