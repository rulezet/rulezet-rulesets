rule TTP_XOR_QUAD_CurrentVersionRun_786a {
  strings:
    $key_786a = { 2b 05 [2] 0f 0b [2] 24 27 [2] 0a 05 [2] 1e 1e [2] 11 04 [2] 0f 19 [2] 0d 18 [2] 16 1e [2] 0a 19 [2] 16 36 }

  condition:
    any of them
}