rule TTP_XOR_QUAD_CurrentVersionRun_0f3c {
  strings:
    $key_0f3c = { 5c 53 [2] 78 5d [2] 53 71 [2] 7d 53 [2] 69 48 [2] 66 52 [2] 78 4f [2] 7a 4e [2] 61 48 [2] 7d 4f [2] 61 60 }

  condition:
    any of them
}