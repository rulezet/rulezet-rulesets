rule TTP_XOR_QUAD_CurrentVersionRun_2102 {
  strings:
    $key_2102 = { 72 6d [2] 56 63 [2] 7d 4f [2] 53 6d [2] 47 76 [2] 48 6c [2] 56 71 [2] 54 70 [2] 4f 76 [2] 53 71 [2] 4f 5e }

  condition:
    any of them
}