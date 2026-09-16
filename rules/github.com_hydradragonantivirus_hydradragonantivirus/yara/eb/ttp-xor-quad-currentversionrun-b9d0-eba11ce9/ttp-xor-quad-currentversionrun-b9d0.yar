rule TTP_XOR_QUAD_CurrentVersionRun_b9d0 {
  strings:
    $key_b9d0 = { ea bf [2] ce b1 [2] e5 9d [2] cb bf [2] df a4 [2] d0 be [2] ce a3 [2] cc a2 [2] d7 a4 [2] cb a3 [2] d7 8c }

  condition:
    any of them
}