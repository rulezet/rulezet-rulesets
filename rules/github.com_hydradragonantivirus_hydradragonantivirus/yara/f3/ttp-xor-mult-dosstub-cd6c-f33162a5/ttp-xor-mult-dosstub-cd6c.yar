rule TTP_XOR_MULT_DOSStub_cd6c {
  strings:
    $key_cd6c = { 99 04 [2] ed 1c [2] aa 1e [2] ed 0f [2] a3 03 [2] af 09 [2] b8 02 [2] a3 4c [2] 9e }

  condition:
    any of them
}