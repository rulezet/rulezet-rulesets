rule TTP_XOR_QUAD_CurrentVersionRun_3012 {
  strings:
    $key_3012 = { 63 7d [2] 47 73 [2] 6c 5f [2] 42 7d [2] 56 66 [2] 59 7c [2] 47 61 [2] 45 60 [2] 5e 66 [2] 42 61 [2] 5e 4e }

  condition:
    any of them
}