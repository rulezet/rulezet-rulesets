rule TTP_XOR_QUAD_CurrentVersionRun_b6a3 {
  strings:
    $key_b6a3 = { e5 cc [2] c1 c2 [2] ea ee [2] c4 cc [2] d0 d7 [2] df cd [2] c1 d0 [2] c3 d1 [2] d8 d7 [2] c4 d0 [2] d8 ff }

  condition:
    any of them
}