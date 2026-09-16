rule TTP_XOR_QUAD_CurrentVersionRun_7a32 {
  strings:
    $key_7a32 = { 29 5d [2] 0d 53 [2] 26 7f [2] 08 5d [2] 1c 46 [2] 13 5c [2] 0d 41 [2] 0f 40 [2] 14 46 [2] 08 41 [2] 14 6e }

  condition:
    any of them
}