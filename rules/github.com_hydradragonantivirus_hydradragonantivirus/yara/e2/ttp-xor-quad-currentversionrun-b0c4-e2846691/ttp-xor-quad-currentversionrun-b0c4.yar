rule TTP_XOR_QUAD_CurrentVersionRun_b0c4 {
  strings:
    $key_b0c4 = { e3 ab [2] c7 a5 [2] ec 89 [2] c2 ab [2] d6 b0 [2] d9 aa [2] c7 b7 [2] c5 b6 [2] de b0 [2] c2 b7 [2] de 98 }

  condition:
    any of them
}