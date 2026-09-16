rule TTP_XOR_QUAD_CurrentVersionRun_05e7 {
  strings:
    $key_05e7 = { 56 88 [2] 72 86 [2] 59 aa [2] 77 88 [2] 63 93 [2] 6c 89 [2] 72 94 [2] 70 95 [2] 6b 93 [2] 77 94 [2] 6b bb }

  condition:
    any of them
}