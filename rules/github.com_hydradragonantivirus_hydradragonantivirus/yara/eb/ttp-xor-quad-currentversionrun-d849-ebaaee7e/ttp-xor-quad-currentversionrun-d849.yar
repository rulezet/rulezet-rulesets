rule TTP_XOR_QUAD_CurrentVersionRun_d849 {
  strings:
    $key_d849 = { 8b 26 [2] af 28 [2] 84 04 [2] aa 26 [2] be 3d [2] b1 27 [2] af 3a [2] ad 3b [2] b6 3d [2] aa 3a [2] b6 15 }

  condition:
    any of them
}