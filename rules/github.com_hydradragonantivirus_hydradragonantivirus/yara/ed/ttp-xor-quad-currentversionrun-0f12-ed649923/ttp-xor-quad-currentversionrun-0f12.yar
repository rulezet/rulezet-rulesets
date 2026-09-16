rule TTP_XOR_QUAD_CurrentVersionRun_0f12 {
  strings:
    $key_0f12 = { 5c 7d [2] 78 73 [2] 53 5f [2] 7d 7d [2] 69 66 [2] 66 7c [2] 78 61 [2] 7a 60 [2] 61 66 [2] 7d 61 [2] 61 4e }

  condition:
    any of them
}