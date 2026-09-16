rule TTP_XOR_MULT_DOSStub_cd9f {
  strings:
    $key_cd9f = { 99 f7 [2] ed ef [2] aa ed [2] ed fc [2] a3 f0 [2] af fa [2] b8 f1 [2] a3 bf [2] 9e }

  condition:
    any of them
}