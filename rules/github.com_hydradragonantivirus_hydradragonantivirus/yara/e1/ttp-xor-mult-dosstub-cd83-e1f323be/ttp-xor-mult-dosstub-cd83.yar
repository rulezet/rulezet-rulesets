rule TTP_XOR_MULT_DOSStub_cd83 {
  strings:
    $key_cd83 = { 99 eb [2] ed f3 [2] aa f1 [2] ed e0 [2] a3 ec [2] af e6 [2] b8 ed [2] a3 a3 [2] 9e }

  condition:
    any of them
}