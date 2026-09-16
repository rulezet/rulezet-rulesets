rule TTP_XOR_MULT_DOSStub_8e99 {
  strings:
    $key_8e99 = { da f1 [2] ae e9 [2] e9 eb [2] ae fa [2] e0 f6 [2] ec fc [2] fb f7 [2] e0 b9 [2] dd }

  condition:
    any of them
}