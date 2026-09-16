rule TTP_XOR_QUAD_CurrentVersionRun_0d02 {
  strings:
    $key_0d02 = { 5e 6d [2] 7a 63 [2] 51 4f [2] 7f 6d [2] 6b 76 [2] 64 6c [2] 7a 71 [2] 78 70 [2] 63 76 [2] 7f 71 [2] 63 5e }

  condition:
    any of them
}