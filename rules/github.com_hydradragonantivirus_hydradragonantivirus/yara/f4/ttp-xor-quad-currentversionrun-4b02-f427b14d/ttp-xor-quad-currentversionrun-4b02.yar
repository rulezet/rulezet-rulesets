rule TTP_XOR_QUAD_CurrentVersionRun_4b02 {
  strings:
    $key_4b02 = { 18 6d [2] 3c 63 [2] 17 4f [2] 39 6d [2] 2d 76 [2] 22 6c [2] 3c 71 [2] 3e 70 [2] 25 76 [2] 39 71 [2] 25 5e }

  condition:
    any of them
}