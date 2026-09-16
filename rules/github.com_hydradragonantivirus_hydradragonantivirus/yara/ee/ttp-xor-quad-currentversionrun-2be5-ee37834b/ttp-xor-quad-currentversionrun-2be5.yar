rule TTP_XOR_QUAD_CurrentVersionRun_2be5 {
  strings:
    $key_2be5 = { 78 8a [2] 5c 84 [2] 77 a8 [2] 59 8a [2] 4d 91 [2] 42 8b [2] 5c 96 [2] 5e 97 [2] 45 91 [2] 59 96 [2] 45 b9 }

  condition:
    any of them
}