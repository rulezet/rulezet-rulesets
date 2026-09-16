rule TTP_XOR_MULT_DOSStub_8e9e {
  strings:
    $key_8e9e = { da f6 [2] ae ee [2] e9 ec [2] ae fd [2] e0 f1 [2] ec fb [2] fb f0 [2] e0 be [2] dd }

  condition:
    any of them
}