rule TTP_XOR_QUAD_CurrentVersionRun_2162 {
  strings:
    $key_2162 = { 72 0d [2] 56 03 [2] 7d 2f [2] 53 0d [2] 47 16 [2] 48 0c [2] 56 11 [2] 54 10 [2] 4f 16 [2] 53 11 [2] 4f 3e }

  condition:
    any of them
}