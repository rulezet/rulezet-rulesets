rule TTP_XOR_QUAD_CurrentVersionRun_eaa9 {
  strings:
    $key_eaa9 = { b9 c6 [2] 9d c8 [2] b6 e4 [2] 98 c6 [2] 8c dd [2] 83 c7 [2] 9d da [2] 9f db [2] 84 dd [2] 98 da [2] 84 f5 }

  condition:
    any of them
}