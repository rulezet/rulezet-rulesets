rule TTP_XOR_QUAD_CurrentVersionRun_b981 {
  strings:
    $key_b981 = { ea ee [2] ce e0 [2] e5 cc [2] cb ee [2] df f5 [2] d0 ef [2] ce f2 [2] cc f3 [2] d7 f5 [2] cb f2 [2] d7 dd }

  condition:
    any of them
}