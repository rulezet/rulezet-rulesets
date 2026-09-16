rule TTP_XOR_QUAD_CurrentVersionRun_b9cc {
  strings:
    $key_b9cc = { ea a3 [2] ce ad [2] e5 81 [2] cb a3 [2] df b8 [2] d0 a2 [2] ce bf [2] cc be [2] d7 b8 [2] cb bf [2] d7 90 }

  condition:
    any of them
}