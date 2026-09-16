rule TTP_XOR_QUAD_CurrentVersionRun_1b32 {
  strings:
    $key_1b32 = { 48 5d [2] 6c 53 [2] 47 7f [2] 69 5d [2] 7d 46 [2] 72 5c [2] 6c 41 [2] 6e 40 [2] 75 46 [2] 69 41 [2] 75 6e }

  condition:
    any of them
}