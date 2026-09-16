rule TTP_XOR_QUAD_CurrentVersionRun_0f21 {
  strings:
    $key_0f21 = { 5c 4e [2] 78 40 [2] 53 6c [2] 7d 4e [2] 69 55 [2] 66 4f [2] 78 52 [2] 7a 53 [2] 61 55 [2] 7d 52 [2] 61 7d }

  condition:
    any of them
}