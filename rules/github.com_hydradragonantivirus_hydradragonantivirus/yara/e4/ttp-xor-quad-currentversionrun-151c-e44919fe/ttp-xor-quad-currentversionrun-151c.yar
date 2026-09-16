rule TTP_XOR_QUAD_CurrentVersionRun_151c {
  strings:
    $key_151c = { 46 73 [2] 62 7d [2] 49 51 [2] 67 73 [2] 73 68 [2] 7c 72 [2] 62 6f [2] 60 6e [2] 7b 68 [2] 67 6f [2] 7b 40 }

  condition:
    any of them
}