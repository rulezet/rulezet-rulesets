rule TTP_XOR_MULT_DOSStub_cd7c {
  strings:
    $key_cd7c = { 99 14 [2] ed 0c [2] aa 0e [2] ed 1f [2] a3 13 [2] af 19 [2] b8 12 [2] a3 5c [2] 9e }

  condition:
    any of them
}