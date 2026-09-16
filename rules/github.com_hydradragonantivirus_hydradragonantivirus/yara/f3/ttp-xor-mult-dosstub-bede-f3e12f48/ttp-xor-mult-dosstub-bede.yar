rule TTP_XOR_MULT_DOSStub_bede {
  strings:
    $key_bede = { ea b6 [2] 9e ae [2] d9 ac [2] 9e bd [2] d0 b1 [2] dc bb [2] cb b0 [2] d0 fe [2] ed }

  condition:
    any of them
}