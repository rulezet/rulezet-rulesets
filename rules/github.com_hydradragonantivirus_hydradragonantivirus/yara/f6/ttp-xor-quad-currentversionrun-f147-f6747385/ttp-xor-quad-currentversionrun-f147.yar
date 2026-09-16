rule TTP_XOR_QUAD_CurrentVersionRun_f147 {
  strings:
    $key_f147 = { a2 28 [2] 86 26 [2] ad 0a [2] 83 28 [2] 97 33 [2] 98 29 [2] 86 34 [2] 84 35 [2] 9f 33 [2] 83 34 [2] 9f 1b }

  condition:
    any of them
}