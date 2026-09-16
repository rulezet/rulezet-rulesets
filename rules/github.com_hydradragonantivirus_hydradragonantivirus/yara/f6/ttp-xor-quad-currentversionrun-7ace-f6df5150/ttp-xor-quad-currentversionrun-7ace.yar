rule TTP_XOR_QUAD_CurrentVersionRun_7ace {
  strings:
    $key_7ace = { 29 a1 [2] 0d af [2] 26 83 [2] 08 a1 [2] 1c ba [2] 13 a0 [2] 0d bd [2] 0f bc [2] 14 ba [2] 08 bd [2] 14 92 }

  condition:
    any of them
}