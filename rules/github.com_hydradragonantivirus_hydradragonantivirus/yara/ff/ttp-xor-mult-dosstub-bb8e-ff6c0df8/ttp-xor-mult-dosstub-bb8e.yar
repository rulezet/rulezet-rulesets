rule TTP_XOR_MULT_DOSStub_bb8e {
  strings:
    $key_bb8e = { ef e6 [2] 9b fe [2] dc fc [2] 9b ed [2] d5 e1 [2] d9 eb [2] ce e0 [2] d5 ae [2] e8 }

  condition:
    any of them
}