rule TTP_XOR_QUAD_CurrentVersionRun_b0d1 {
  strings:
    $key_b0d1 = { e3 be [2] c7 b0 [2] ec 9c [2] c2 be [2] d6 a5 [2] d9 bf [2] c7 a2 [2] c5 a3 [2] de a5 [2] c2 a2 [2] de 8d }

  condition:
    any of them
}