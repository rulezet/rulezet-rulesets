rule TTP_XOR_MULT_DOSStub_cdb8 {
  strings:
    $key_cdb8 = { 99 d0 [2] ed c8 [2] aa ca [2] ed db [2] a3 d7 [2] af dd [2] b8 d6 [2] a3 98 [2] 9e }

  condition:
    any of them
}