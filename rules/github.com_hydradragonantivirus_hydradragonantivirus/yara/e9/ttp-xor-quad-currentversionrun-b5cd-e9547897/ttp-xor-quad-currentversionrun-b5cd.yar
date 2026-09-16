rule TTP_XOR_QUAD_CurrentVersionRun_b5cd {
  strings:
    $key_b5cd = { e6 a2 [2] c2 ac [2] e9 80 [2] c7 a2 [2] d3 b9 [2] dc a3 [2] c2 be [2] c0 bf [2] db b9 [2] c7 be [2] db 91 }

  condition:
    any of them
}