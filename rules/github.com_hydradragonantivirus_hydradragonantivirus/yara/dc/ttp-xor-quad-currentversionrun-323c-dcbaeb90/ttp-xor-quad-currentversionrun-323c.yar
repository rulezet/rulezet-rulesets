rule TTP_XOR_QUAD_CurrentVersionRun_323c {
  strings:
    $key_323c = { 61 53 [2] 45 5d [2] 6e 71 [2] 40 53 [2] 54 48 [2] 5b 52 [2] 45 4f [2] 47 4e [2] 5c 48 [2] 40 4f [2] 5c 60 }

  condition:
    any of them
}