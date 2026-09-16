rule TTP_XOR_QUAD_CurrentVersionRun_ccd3 {
  strings:
    $key_ccd3 = { 9f bc [2] bb b2 [2] 90 9e [2] be bc [2] aa a7 [2] a5 bd [2] bb a0 [2] b9 a1 [2] a2 a7 [2] be a0 [2] a2 8f }

  condition:
    any of them
}