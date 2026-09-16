rule TTP_XOR_QUAD_CurrentVersionRun_353c {
  strings:
    $key_353c = { 66 53 [2] 42 5d [2] 69 71 [2] 47 53 [2] 53 48 [2] 5c 52 [2] 42 4f [2] 40 4e [2] 5b 48 [2] 47 4f [2] 5b 60 }

  condition:
    any of them
}