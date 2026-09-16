rule TTP_XOR_MULT_DOSStub_becd {
  strings:
    $key_becd = { ea a5 [2] 9e bd [2] d9 bf [2] 9e ae [2] d0 a2 [2] dc a8 [2] cb a3 [2] d0 ed [2] ed }

  condition:
    any of them
}