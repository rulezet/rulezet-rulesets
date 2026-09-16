rule TTP_XOR_QUAD_CurrentVersionRun_b9ca {
  strings:
    $key_b9ca = { ea a5 [2] ce ab [2] e5 87 [2] cb a5 [2] df be [2] d0 a4 [2] ce b9 [2] cc b8 [2] d7 be [2] cb b9 [2] d7 96 }

  condition:
    any of them
}