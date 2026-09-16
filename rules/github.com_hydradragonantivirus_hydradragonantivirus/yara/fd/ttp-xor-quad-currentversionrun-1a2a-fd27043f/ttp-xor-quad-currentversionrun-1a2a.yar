rule TTP_XOR_QUAD_CurrentVersionRun_1a2a {
  strings:
    $key_1a2a = { 49 45 [2] 6d 4b [2] 46 67 [2] 68 45 [2] 7c 5e [2] 73 44 [2] 6d 59 [2] 6f 58 [2] 74 5e [2] 68 59 [2] 74 76 }

  condition:
    any of them
}