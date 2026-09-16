rule TTP_XOR_QUAD_CurrentVersionRun_132a {
  strings:
    $key_132a = { 40 45 [2] 64 4b [2] 4f 67 [2] 61 45 [2] 75 5e [2] 7a 44 [2] 64 59 [2] 66 58 [2] 7d 5e [2] 61 59 [2] 7d 76 }

  condition:
    any of them
}