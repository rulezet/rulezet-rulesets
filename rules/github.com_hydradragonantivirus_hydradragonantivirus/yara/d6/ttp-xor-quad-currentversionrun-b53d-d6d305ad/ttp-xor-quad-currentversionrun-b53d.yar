rule TTP_XOR_QUAD_CurrentVersionRun_b53d {
  strings:
    $key_b53d = { e6 52 [2] c2 5c [2] e9 70 [2] c7 52 [2] d3 49 [2] dc 53 [2] c2 4e [2] c0 4f [2] db 49 [2] c7 4e [2] db 61 }

  condition:
    any of them
}