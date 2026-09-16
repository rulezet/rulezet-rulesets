rule TTP_XOR_MULT_DOSStub_aebf {
  strings:
    $key_aebf = { fa d7 [2] 8e cf [2] c9 cd [2] 8e dc [2] c0 d0 [2] cc da [2] db d1 [2] c0 9f [2] fd }

  condition:
    any of them
}