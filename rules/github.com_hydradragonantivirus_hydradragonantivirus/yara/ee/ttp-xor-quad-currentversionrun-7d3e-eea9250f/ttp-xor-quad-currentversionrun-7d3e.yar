rule TTP_XOR_QUAD_CurrentVersionRun_7d3e {
  strings:
    $key_7d3e = { 2e 51 [2] 0a 5f [2] 21 73 [2] 0f 51 [2] 1b 4a [2] 14 50 [2] 0a 4d [2] 08 4c [2] 13 4a [2] 0f 4d [2] 13 62 }

  condition:
    any of them
}