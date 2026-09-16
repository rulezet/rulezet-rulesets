rule TTP_XOR_QUAD_CurrentVersionRun_b9b3 {
  strings:
    $key_b9b3 = { ea dc [2] ce d2 [2] e5 fe [2] cb dc [2] df c7 [2] d0 dd [2] ce c0 [2] cc c1 [2] d7 c7 [2] cb c0 [2] d7 ef }

  condition:
    any of them
}