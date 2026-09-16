rule TTP_XOR_QUAD_CurrentVersionRun_e6a2 {
  strings:
    $key_e6a2 = { b5 cd [2] 91 c3 [2] ba ef [2] 94 cd [2] 80 d6 [2] 8f cc [2] 91 d1 [2] 93 d0 [2] 88 d6 [2] 94 d1 [2] 88 fe }

  condition:
    any of them
}