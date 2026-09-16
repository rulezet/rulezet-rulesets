rule TTP_XOR_QUAD_CurrentVersionRun_026a {
  strings:
    $key_026a = { 51 05 [2] 75 0b [2] 5e 27 [2] 70 05 [2] 64 1e [2] 6b 04 [2] 75 19 [2] 77 18 [2] 6c 1e [2] 70 19 [2] 6c 36 }

  condition:
    any of them
}