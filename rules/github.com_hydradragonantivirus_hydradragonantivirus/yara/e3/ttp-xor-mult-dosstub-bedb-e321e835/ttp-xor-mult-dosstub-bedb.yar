rule TTP_XOR_MULT_DOSStub_bedb {
  strings:
    $key_bedb = { ea b3 [2] 9e ab [2] d9 a9 [2] 9e b8 [2] d0 b4 [2] dc be [2] cb b5 [2] d0 fb [2] ed }

  condition:
    any of them
}