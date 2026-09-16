rule TTP_XOR_MULT_DOSStub_748e {
  strings:
    $key_748e = { 20 e6 [2] 54 fe [2] 13 fc [2] 54 ed [2] 1a e1 [2] 16 eb [2] 01 e0 [2] 1a ae [2] 27 }

  condition:
    any of them
}