rule TTP_XOR_QUAD_CurrentVersionRun_6111 {
  strings:
    $key_6111 = { 32 7e [2] 16 70 [2] 3d 5c [2] 13 7e [2] 07 65 [2] 08 7f [2] 16 62 [2] 14 63 [2] 0f 65 [2] 13 62 [2] 0f 4d }

  condition:
    any of them
}