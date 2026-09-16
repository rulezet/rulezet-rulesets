rule TTP_XOR_QUAD_CurrentVersionRun_3f31 {
  strings:
    $key_3f31 = { 6c 5e [2] 48 50 [2] 63 7c [2] 4d 5e [2] 59 45 [2] 56 5f [2] 48 42 [2] 4a 43 [2] 51 45 [2] 4d 42 [2] 51 6d }

  condition:
    any of them
}