rule TTP_XOR_QUAD_CurrentVersionRun_bf91 {
  strings:
    $key_bf91 = { ec fe [2] c8 f0 [2] e3 dc [2] cd fe [2] d9 e5 [2] d6 ff [2] c8 e2 [2] ca e3 [2] d1 e5 [2] cd e2 [2] d1 cd }

  condition:
    any of them
}