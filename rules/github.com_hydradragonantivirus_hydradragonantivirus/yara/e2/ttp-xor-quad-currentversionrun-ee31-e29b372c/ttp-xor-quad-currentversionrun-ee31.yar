rule TTP_XOR_QUAD_CurrentVersionRun_ee31 {
  strings:
    $key_ee31 = { bd 5e [2] 99 50 [2] b2 7c [2] 9c 5e [2] 88 45 [2] 87 5f [2] 99 42 [2] 9b 43 [2] 80 45 [2] 9c 42 [2] 80 6d }

  condition:
    any of them
}