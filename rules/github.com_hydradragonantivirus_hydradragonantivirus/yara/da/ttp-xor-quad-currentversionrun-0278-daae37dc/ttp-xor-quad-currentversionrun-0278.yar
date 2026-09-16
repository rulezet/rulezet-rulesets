rule TTP_XOR_QUAD_CurrentVersionRun_0278 {
  strings:
    $key_0278 = { 51 17 [2] 75 19 [2] 5e 35 [2] 70 17 [2] 64 0c [2] 6b 16 [2] 75 0b [2] 77 0a [2] 6c 0c [2] 70 0b [2] 6c 24 }

  condition:
    any of them
}