rule TTP_XOR_MULT_DOSStub_cd93 {
  strings:
    $key_cd93 = { 99 fb [2] ed e3 [2] aa e1 [2] ed f0 [2] a3 fc [2] af f6 [2] b8 fd [2] a3 b3 [2] 9e }

  condition:
    any of them
}