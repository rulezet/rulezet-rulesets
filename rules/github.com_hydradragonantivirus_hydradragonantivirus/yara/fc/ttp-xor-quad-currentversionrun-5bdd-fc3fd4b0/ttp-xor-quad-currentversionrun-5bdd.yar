rule TTP_XOR_QUAD_CurrentVersionRun_5bdd {
  strings:
    $key_5bdd = { 08 b2 [2] 2c bc [2] 07 90 [2] 29 b2 [2] 3d a9 [2] 32 b3 [2] 2c ae [2] 2e af [2] 35 a9 [2] 29 ae [2] 35 81 }

  condition:
    any of them
}