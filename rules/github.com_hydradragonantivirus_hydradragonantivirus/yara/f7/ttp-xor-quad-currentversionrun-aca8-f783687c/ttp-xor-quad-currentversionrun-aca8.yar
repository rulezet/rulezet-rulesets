rule TTP_XOR_QUAD_CurrentVersionRun_aca8 {
  strings:
    $key_aca8 = { ff c7 [2] db c9 [2] f0 e5 [2] de c7 [2] ca dc [2] c5 c6 [2] db db [2] d9 da [2] c2 dc [2] de db [2] c2 f4 }

  condition:
    any of them
}