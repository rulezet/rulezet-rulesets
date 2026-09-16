rule TTP_XOR_QUAD_CurrentVersionRun_6512 {
  strings:
    $key_6512 = { 36 7d [2] 12 73 [2] 39 5f [2] 17 7d [2] 03 66 [2] 0c 7c [2] 12 61 [2] 10 60 [2] 0b 66 [2] 17 61 [2] 0b 4e }

  condition:
    any of them
}