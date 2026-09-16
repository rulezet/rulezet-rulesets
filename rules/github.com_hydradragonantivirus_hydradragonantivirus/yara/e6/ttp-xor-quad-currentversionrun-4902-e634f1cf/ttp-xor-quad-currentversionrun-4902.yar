rule TTP_XOR_QUAD_CurrentVersionRun_4902 {
  strings:
    $key_4902 = { 1a 6d [2] 3e 63 [2] 15 4f [2] 3b 6d [2] 2f 76 [2] 20 6c [2] 3e 71 [2] 3c 70 [2] 27 76 [2] 3b 71 [2] 27 5e }

  condition:
    any of them
}