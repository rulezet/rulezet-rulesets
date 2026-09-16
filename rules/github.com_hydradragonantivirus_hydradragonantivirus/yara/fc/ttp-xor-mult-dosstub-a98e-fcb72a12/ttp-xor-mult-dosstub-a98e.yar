rule TTP_XOR_MULT_DOSStub_a98e {
  strings:
    $key_a98e = { fd e6 [2] 89 fe [2] ce fc [2] 89 ed [2] c7 e1 [2] cb eb [2] dc e0 [2] c7 ae [2] fa }

  condition:
    any of them
}