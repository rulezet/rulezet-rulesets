rule TTP_XOR_QUAD_CurrentVersionRun_ee14 {
  strings:
    $key_ee14 = { bd 7b [2] 99 75 [2] b2 59 [2] 9c 7b [2] 88 60 [2] 87 7a [2] 99 67 [2] 9b 66 [2] 80 60 [2] 9c 67 [2] 80 48 }

  condition:
    any of them
}