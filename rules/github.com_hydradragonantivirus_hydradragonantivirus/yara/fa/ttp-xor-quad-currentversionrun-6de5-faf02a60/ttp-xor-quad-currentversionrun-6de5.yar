rule TTP_XOR_QUAD_CurrentVersionRun_6de5 {
  strings:
    $key_6de5 = { 3e 8a [2] 1a 84 [2] 31 a8 [2] 1f 8a [2] 0b 91 [2] 04 8b [2] 1a 96 [2] 18 97 [2] 03 91 [2] 1f 96 [2] 03 b9 }

  condition:
    any of them
}