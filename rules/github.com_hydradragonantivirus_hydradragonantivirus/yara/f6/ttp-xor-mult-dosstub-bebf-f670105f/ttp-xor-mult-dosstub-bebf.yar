rule TTP_XOR_MULT_DOSStub_bebf {
  strings:
    $key_bebf = { ea d7 [2] 9e cf [2] d9 cd [2] 9e dc [2] d0 d0 [2] dc da [2] cb d1 [2] d0 9f [2] ed }

  condition:
    any of them
}