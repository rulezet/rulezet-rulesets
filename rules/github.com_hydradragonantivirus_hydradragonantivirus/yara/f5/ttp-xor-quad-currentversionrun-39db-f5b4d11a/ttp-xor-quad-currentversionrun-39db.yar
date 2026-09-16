rule TTP_XOR_QUAD_CurrentVersionRun_39db {
  strings:
    $key_39db = { 6a b4 [2] 4e ba [2] 65 96 [2] 4b b4 [2] 5f af [2] 50 b5 [2] 4e a8 [2] 4c a9 [2] 57 af [2] 4b a8 [2] 57 87 }

  condition:
    any of them
}