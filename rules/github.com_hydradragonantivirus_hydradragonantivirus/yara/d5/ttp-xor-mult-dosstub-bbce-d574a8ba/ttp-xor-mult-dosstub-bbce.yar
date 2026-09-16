rule TTP_XOR_MULT_DOSStub_bbce {
  strings:
    $key_bbce = { ef a6 [2] 9b be [2] dc bc [2] 9b ad [2] d5 a1 [2] d9 ab [2] ce a0 [2] d5 ee [2] e8 }

  condition:
    any of them
}