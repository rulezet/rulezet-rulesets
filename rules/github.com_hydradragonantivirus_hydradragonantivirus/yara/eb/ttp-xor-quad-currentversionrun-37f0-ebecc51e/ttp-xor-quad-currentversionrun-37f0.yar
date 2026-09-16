rule TTP_XOR_QUAD_CurrentVersionRun_37f0 {
  strings:
    $key_37f0 = { 64 9f [2] 40 91 [2] 6b bd [2] 45 9f [2] 51 84 [2] 5e 9e [2] 40 83 [2] 42 82 [2] 59 84 [2] 45 83 [2] 59 ac }

  condition:
    any of them
}