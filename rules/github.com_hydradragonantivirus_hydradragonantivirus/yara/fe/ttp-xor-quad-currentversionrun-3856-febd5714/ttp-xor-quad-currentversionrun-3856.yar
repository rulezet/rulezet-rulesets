rule TTP_XOR_QUAD_CurrentVersionRun_3856 {
  strings:
    $key_3856 = { 6b 39 [2] 4f 37 [2] 64 1b [2] 4a 39 [2] 5e 22 [2] 51 38 [2] 4f 25 [2] 4d 24 [2] 56 22 [2] 4a 25 [2] 56 0a }

  condition:
    any of them
}