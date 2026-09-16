rule TTP_XOR_QUAD_CurrentVersionRun_3031 {
  strings:
    $key_3031 = { 63 5e [2] 47 50 [2] 6c 7c [2] 42 5e [2] 56 45 [2] 59 5f [2] 47 42 [2] 45 43 [2] 5e 45 [2] 42 42 [2] 5e 6d }

  condition:
    any of them
}