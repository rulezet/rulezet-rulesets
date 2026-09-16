rule TTP_XOR_QUAD_CurrentVersionRun_3f02 {
  strings:
    $key_3f02 = { 6c 6d [2] 48 63 [2] 63 4f [2] 4d 6d [2] 59 76 [2] 56 6c [2] 48 71 [2] 4a 70 [2] 51 76 [2] 4d 71 [2] 51 5e }

  condition:
    any of them
}