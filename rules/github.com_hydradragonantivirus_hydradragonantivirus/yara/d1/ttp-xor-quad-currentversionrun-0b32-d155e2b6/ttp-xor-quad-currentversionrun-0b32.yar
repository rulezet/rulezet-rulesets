rule TTP_XOR_QUAD_CurrentVersionRun_0b32 {
  strings:
    $key_0b32 = { 58 5d [2] 7c 53 [2] 57 7f [2] 79 5d [2] 6d 46 [2] 62 5c [2] 7c 41 [2] 7e 40 [2] 65 46 [2] 79 41 [2] 65 6e }

  condition:
    any of them
}