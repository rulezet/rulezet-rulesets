rule TTP_XOR_QUAD_CurrentVersionRun_ccd2 {
  strings:
    $key_ccd2 = { 9f bd [2] bb b3 [2] 90 9f [2] be bd [2] aa a6 [2] a5 bc [2] bb a1 [2] b9 a0 [2] a2 a6 [2] be a1 [2] a2 8e }

  condition:
    any of them
}