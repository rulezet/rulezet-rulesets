rule TTP_XOR_MULT_DOSStub_aecd {
  strings:
    $key_aecd = { fa a5 [2] 8e bd [2] c9 bf [2] 8e ae [2] c0 a2 [2] cc a8 [2] db a3 [2] c0 ed [2] fd }

  condition:
    any of them
}