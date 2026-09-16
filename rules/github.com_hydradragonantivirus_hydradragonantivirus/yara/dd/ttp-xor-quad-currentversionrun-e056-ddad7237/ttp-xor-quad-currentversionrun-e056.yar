rule TTP_XOR_QUAD_CurrentVersionRun_e056 {
  strings:
    $key_e056 = { b3 39 [2] 97 37 [2] bc 1b [2] 92 39 [2] 86 22 [2] 89 38 [2] 97 25 [2] 95 24 [2] 8e 22 [2] 92 25 [2] 8e 0a }

  condition:
    any of them
}