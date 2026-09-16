rule TTP_XOR_QUAD_CurrentVersionRun_bbcf {
  strings:
    $key_bbcf = { e8 a0 [2] cc ae [2] e7 82 [2] c9 a0 [2] dd bb [2] d2 a1 [2] cc bc [2] ce bd [2] d5 bb [2] c9 bc [2] d5 93 }

  condition:
    any of them
}