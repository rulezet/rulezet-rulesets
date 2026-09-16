rule TTP_XOR_MULT_DOSStub_cd91 {
  strings:
    $key_cd91 = { 99 f9 [2] ed e1 [2] aa e3 [2] ed f2 [2] a3 fe [2] af f4 [2] b8 ff [2] a3 b1 [2] 9e }

  condition:
    any of them
}