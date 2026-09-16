rule TTP_XOR_MULT_DOSStub_becb {
  strings:
    $key_becb = { ea a3 [2] 9e bb [2] d9 b9 [2] 9e a8 [2] d0 a4 [2] dc ae [2] cb a5 [2] d0 eb [2] ed }

  condition:
    any of them
}