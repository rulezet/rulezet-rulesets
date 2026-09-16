rule TTP_XOR_QUAD_CurrentVersionRun_ffb3 {
  strings:
    $key_ffb3 = { ac dc [2] 88 d2 [2] a3 fe [2] 8d dc [2] 99 c7 [2] 96 dd [2] 88 c0 [2] 8a c1 [2] 91 c7 [2] 8d c0 [2] 91 ef }

  condition:
    any of them
}