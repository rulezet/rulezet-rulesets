rule TTP_XOR_QUAD_CurrentVersionRun_296b {
  strings:
    $key_296b = { 7a 04 [2] 5e 0a [2] 75 26 [2] 5b 04 [2] 4f 1f [2] 40 05 [2] 5e 18 [2] 5c 19 [2] 47 1f [2] 5b 18 [2] 47 37 }

  condition:
    any of them
}