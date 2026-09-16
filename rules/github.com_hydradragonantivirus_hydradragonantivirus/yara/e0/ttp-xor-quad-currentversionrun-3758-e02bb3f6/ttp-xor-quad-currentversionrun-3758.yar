rule TTP_XOR_QUAD_CurrentVersionRun_3758 {
  strings:
    $key_3758 = { 64 37 [2] 40 39 [2] 6b 15 [2] 45 37 [2] 51 2c [2] 5e 36 [2] 40 2b [2] 42 2a [2] 59 2c [2] 45 2b [2] 59 04 }

  condition:
    any of them
}