rule TTP_XOR_MULT_DOSStub_cd0b {
  strings:
    $key_cd0b = { 99 63 [2] ed 7b [2] aa 79 [2] ed 68 [2] a3 64 [2] af 6e [2] b8 65 [2] a3 2b [2] 9e }

  condition:
    any of them
}