rule TTP_XOR_MULT_DOSStub_aeac {
  strings:
    $key_aeac = { fa c4 [2] 8e dc [2] c9 de [2] 8e cf [2] c0 c3 [2] cc c9 [2] db c2 [2] c0 8c [2] fd }

  condition:
    any of them
}