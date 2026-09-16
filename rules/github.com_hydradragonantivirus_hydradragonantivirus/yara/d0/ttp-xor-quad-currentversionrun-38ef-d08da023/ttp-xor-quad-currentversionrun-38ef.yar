rule TTP_XOR_QUAD_CurrentVersionRun_38ef {
  strings:
    $key_38ef = { 6b 80 [2] 4f 8e [2] 64 a2 [2] 4a 80 [2] 5e 9b [2] 51 81 [2] 4f 9c [2] 4d 9d [2] 56 9b [2] 4a 9c [2] 56 b3 }

  condition:
    any of them
}