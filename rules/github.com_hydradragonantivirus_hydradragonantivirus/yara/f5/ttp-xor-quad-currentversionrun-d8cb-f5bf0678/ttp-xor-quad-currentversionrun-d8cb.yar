rule TTP_XOR_QUAD_CurrentVersionRun_d8cb {
  strings:
    $key_d8cb = { 8b a4 [2] af aa [2] 84 86 [2] aa a4 [2] be bf [2] b1 a5 [2] af b8 [2] ad b9 [2] b6 bf [2] aa b8 [2] b6 97 }

  condition:
    any of them
}