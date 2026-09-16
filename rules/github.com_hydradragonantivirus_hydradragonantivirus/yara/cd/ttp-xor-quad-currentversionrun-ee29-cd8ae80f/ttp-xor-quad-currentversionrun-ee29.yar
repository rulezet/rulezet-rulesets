rule TTP_XOR_QUAD_CurrentVersionRun_ee29 {
  strings:
    $key_ee29 = { bd 46 [2] 99 48 [2] b2 64 [2] 9c 46 [2] 88 5d [2] 87 47 [2] 99 5a [2] 9b 5b [2] 80 5d [2] 9c 5a [2] 80 75 }

  condition:
    any of them
}