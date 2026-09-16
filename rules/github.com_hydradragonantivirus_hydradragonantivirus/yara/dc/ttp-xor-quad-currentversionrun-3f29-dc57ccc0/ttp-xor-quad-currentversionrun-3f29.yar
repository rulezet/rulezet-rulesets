rule TTP_XOR_QUAD_CurrentVersionRun_3f29 {
  strings:
    $key_3f29 = { 6c 46 [2] 48 48 [2] 63 64 [2] 4d 46 [2] 59 5d [2] 56 47 [2] 48 5a [2] 4a 5b [2] 51 5d [2] 4d 5a [2] 51 75 }

  condition:
    any of them
}