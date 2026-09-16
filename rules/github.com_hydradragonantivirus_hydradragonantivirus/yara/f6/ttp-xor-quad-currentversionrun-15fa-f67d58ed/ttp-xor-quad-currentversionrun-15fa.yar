rule TTP_XOR_QUAD_CurrentVersionRun_15fa {
  strings:
    $key_15fa = { 46 95 [2] 62 9b [2] 49 b7 [2] 67 95 [2] 73 8e [2] 7c 94 [2] 62 89 [2] 60 88 [2] 7b 8e [2] 67 89 [2] 7b a6 }

  condition:
    any of them
}