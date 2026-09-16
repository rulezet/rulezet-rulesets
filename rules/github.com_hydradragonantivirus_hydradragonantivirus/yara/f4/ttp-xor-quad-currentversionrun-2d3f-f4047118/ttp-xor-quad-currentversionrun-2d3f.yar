rule TTP_XOR_QUAD_CurrentVersionRun_2d3f {
  strings:
    $key_2d3f = { 7e 50 [2] 5a 5e [2] 71 72 [2] 5f 50 [2] 4b 4b [2] 44 51 [2] 5a 4c [2] 58 4d [2] 43 4b [2] 5f 4c [2] 43 63 }

  condition:
    any of them
}