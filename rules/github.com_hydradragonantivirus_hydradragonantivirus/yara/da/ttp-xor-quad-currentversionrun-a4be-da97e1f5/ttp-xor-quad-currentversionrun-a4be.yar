rule TTP_XOR_QUAD_CurrentVersionRun_a4be {
  strings:
    $key_a4be = { f7 d1 [2] d3 df [2] f8 f3 [2] d6 d1 [2] c2 ca [2] cd d0 [2] d3 cd [2] d1 cc [2] ca ca [2] d6 cd [2] ca e2 }

  condition:
    any of them
}