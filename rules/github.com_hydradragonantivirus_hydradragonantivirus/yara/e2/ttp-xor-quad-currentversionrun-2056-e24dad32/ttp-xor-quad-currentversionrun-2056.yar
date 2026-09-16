rule TTP_XOR_QUAD_CurrentVersionRun_2056 {
  strings:
    $key_2056 = { 73 39 [2] 57 37 [2] 7c 1b [2] 52 39 [2] 46 22 [2] 49 38 [2] 57 25 [2] 55 24 [2] 4e 22 [2] 52 25 [2] 4e 0a }

  condition:
    any of them
}