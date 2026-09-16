rule TTP_XOR_QUAD_CurrentVersionRun_0a32 {
  strings:
    $key_0a32 = { 59 5d [2] 7d 53 [2] 56 7f [2] 78 5d [2] 6c 46 [2] 63 5c [2] 7d 41 [2] 7f 40 [2] 64 46 [2] 78 41 [2] 64 6e }

  condition:
    any of them
}