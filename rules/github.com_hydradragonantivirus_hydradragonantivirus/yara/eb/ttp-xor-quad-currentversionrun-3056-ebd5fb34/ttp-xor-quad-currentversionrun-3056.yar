rule TTP_XOR_QUAD_CurrentVersionRun_3056 {
  strings:
    $key_3056 = { 63 39 [2] 47 37 [2] 6c 1b [2] 42 39 [2] 56 22 [2] 59 38 [2] 47 25 [2] 45 24 [2] 5e 22 [2] 42 25 [2] 5e 0a }

  condition:
    any of them
}