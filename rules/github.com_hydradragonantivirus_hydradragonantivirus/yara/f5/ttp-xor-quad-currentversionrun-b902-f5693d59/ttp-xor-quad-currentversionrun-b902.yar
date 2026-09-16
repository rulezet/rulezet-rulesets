rule TTP_XOR_QUAD_CurrentVersionRun_b902 {
  strings:
    $key_b902 = { ea 6d [2] ce 63 [2] e5 4f [2] cb 6d [2] df 76 [2] d0 6c [2] ce 71 [2] cc 70 [2] d7 76 [2] cb 71 [2] d7 5e }

  condition:
    any of them
}