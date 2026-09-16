rule TTP_XOR_QUAD_CurrentVersionRun_570e {
  strings:
    $key_570e = { 04 61 [2] 20 6f [2] 0b 43 [2] 25 61 [2] 31 7a [2] 3e 60 [2] 20 7d [2] 22 7c [2] 39 7a [2] 25 7d [2] 39 52 }

  condition:
    any of them
}