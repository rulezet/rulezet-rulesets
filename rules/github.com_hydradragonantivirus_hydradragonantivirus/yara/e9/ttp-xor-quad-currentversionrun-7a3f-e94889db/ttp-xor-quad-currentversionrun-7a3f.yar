rule TTP_XOR_QUAD_CurrentVersionRun_7a3f {
  strings:
    $key_7a3f = { 29 50 [2] 0d 5e [2] 26 72 [2] 08 50 [2] 1c 4b [2] 13 51 [2] 0d 4c [2] 0f 4d [2] 14 4b [2] 08 4c [2] 14 63 }

  condition:
    any of them
}