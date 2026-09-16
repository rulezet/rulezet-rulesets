rule TTP_XOR_QUAD_CurrentVersionRun_21e7 {
  strings:
    $key_21e7 = { 72 88 [2] 56 86 [2] 7d aa [2] 53 88 [2] 47 93 [2] 48 89 [2] 56 94 [2] 54 95 [2] 4f 93 [2] 53 94 [2] 4f bb }

  condition:
    any of them
}