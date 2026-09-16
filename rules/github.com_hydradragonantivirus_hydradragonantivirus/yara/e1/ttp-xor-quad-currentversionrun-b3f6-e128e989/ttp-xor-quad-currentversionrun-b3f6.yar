rule TTP_XOR_QUAD_CurrentVersionRun_b3f6 {
  strings:
    $key_b3f6 = { e0 99 [2] c4 97 [2] ef bb [2] c1 99 [2] d5 82 [2] da 98 [2] c4 85 [2] c6 84 [2] dd 82 [2] c1 85 [2] dd aa }

  condition:
    any of them
}