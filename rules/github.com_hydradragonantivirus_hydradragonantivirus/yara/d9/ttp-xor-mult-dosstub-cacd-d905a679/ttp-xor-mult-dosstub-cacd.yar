rule TTP_XOR_MULT_DOSStub_cacd {
  strings:
    $key_cacd = { 9e a5 [2] ea bd [2] ad bf [2] ea ae [2] a4 a2 [2] a8 a8 [2] bf a3 [2] a4 ed [2] 99 }

  condition:
    any of them
}