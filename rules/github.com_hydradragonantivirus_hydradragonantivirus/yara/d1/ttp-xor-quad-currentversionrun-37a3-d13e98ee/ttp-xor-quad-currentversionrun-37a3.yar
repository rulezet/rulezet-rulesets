rule TTP_XOR_QUAD_CurrentVersionRun_37a3 {
  strings:
    $key_37a3 = { 64 cc [2] 40 c2 [2] 6b ee [2] 45 cc [2] 51 d7 [2] 5e cd [2] 40 d0 [2] 42 d1 [2] 59 d7 [2] 45 d0 [2] 59 ff }

  condition:
    any of them
}