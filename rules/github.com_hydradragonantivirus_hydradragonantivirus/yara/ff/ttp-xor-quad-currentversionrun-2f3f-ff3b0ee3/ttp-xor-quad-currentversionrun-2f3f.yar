rule TTP_XOR_QUAD_CurrentVersionRun_2f3f {
  strings:
    $key_2f3f = { 7c 50 [2] 58 5e [2] 73 72 [2] 5d 50 [2] 49 4b [2] 46 51 [2] 58 4c [2] 5a 4d [2] 41 4b [2] 5d 4c [2] 41 63 }

  condition:
    any of them
}