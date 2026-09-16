rule TTP_XOR_QUAD_CurrentVersionRun_15fd {
  strings:
    $key_15fd = { 46 92 [2] 62 9c [2] 49 b0 [2] 67 92 [2] 73 89 [2] 7c 93 [2] 62 8e [2] 60 8f [2] 7b 89 [2] 67 8e [2] 7b a1 }

  condition:
    any of them
}