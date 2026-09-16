rule TTP_XOR_QUAD_CurrentVersionRun_57e0 {
  strings:
    $key_57e0 = { 04 8f [2] 20 81 [2] 0b ad [2] 25 8f [2] 31 94 [2] 3e 8e [2] 20 93 [2] 22 92 [2] 39 94 [2] 25 93 [2] 39 bc }

  condition:
    any of them
}