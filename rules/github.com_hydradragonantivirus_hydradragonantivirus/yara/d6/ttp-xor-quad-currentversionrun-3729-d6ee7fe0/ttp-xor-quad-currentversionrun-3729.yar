rule TTP_XOR_QUAD_CurrentVersionRun_3729 {
  strings:
    $key_3729 = { 64 46 [2] 40 48 [2] 6b 64 [2] 45 46 [2] 51 5d [2] 5e 47 [2] 40 5a [2] 42 5b [2] 59 5d [2] 45 5a [2] 59 75 }

  condition:
    any of them
}