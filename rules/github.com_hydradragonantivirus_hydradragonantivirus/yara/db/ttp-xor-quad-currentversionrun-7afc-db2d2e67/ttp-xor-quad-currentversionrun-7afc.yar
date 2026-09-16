rule TTP_XOR_QUAD_CurrentVersionRun_7afc {
  strings:
    $key_7afc = { 29 93 [2] 0d 9d [2] 26 b1 [2] 08 93 [2] 1c 88 [2] 13 92 [2] 0d 8f [2] 0f 8e [2] 14 88 [2] 08 8f [2] 14 a0 }

  condition:
    any of them
}