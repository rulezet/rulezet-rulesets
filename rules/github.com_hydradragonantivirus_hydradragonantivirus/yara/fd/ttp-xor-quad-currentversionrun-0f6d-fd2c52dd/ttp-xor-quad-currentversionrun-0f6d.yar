rule TTP_XOR_QUAD_CurrentVersionRun_0f6d {
  strings:
    $key_0f6d = { 5c 02 [2] 78 0c [2] 53 20 [2] 7d 02 [2] 69 19 [2] 66 03 [2] 78 1e [2] 7a 1f [2] 61 19 [2] 7d 1e [2] 61 31 }

  condition:
    any of them
}