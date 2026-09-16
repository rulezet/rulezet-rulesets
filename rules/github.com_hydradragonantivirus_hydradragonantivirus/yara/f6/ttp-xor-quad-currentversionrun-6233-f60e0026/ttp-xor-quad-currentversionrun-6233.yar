rule TTP_XOR_QUAD_CurrentVersionRun_6233 {
  strings:
    $key_6233 = { 31 5c [2] 15 52 [2] 3e 7e [2] 10 5c [2] 04 47 [2] 0b 5d [2] 15 40 [2] 17 41 [2] 0c 47 [2] 10 40 [2] 0c 6f }

  condition:
    any of them
}