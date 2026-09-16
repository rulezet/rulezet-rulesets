rule TTP_XOR_QUAD_CurrentVersionRun_013f {
  strings:
    $key_013f = { 52 50 [2] 76 5e [2] 5d 72 [2] 73 50 [2] 67 4b [2] 68 51 [2] 76 4c [2] 74 4d [2] 6f 4b [2] 73 4c [2] 6f 63 }

  condition:
    any of them
}