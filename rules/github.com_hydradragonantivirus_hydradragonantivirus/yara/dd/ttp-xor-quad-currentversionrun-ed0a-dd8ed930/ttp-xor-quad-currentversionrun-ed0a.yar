rule TTP_XOR_QUAD_CurrentVersionRun_ed0a {
  strings:
    $key_ed0a = { be 65 [2] 9a 6b [2] b1 47 [2] 9f 65 [2] 8b 7e [2] 84 64 [2] 9a 79 [2] 98 78 [2] 83 7e [2] 9f 79 [2] 83 56 }

  condition:
    any of them
}