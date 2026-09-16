rule TTP_XOR_QUAD_CurrentVersionRun_e505 {
  strings:
    $key_e505 = { b6 6a [2] 92 64 [2] b9 48 [2] 97 6a [2] 83 71 [2] 8c 6b [2] 92 76 [2] 90 77 [2] 8b 71 [2] 97 76 [2] 8b 59 }

  condition:
    any of them
}