rule TTP_XOR_QUAD_CurrentVersionRun_b190 {
  strings:
    $key_b190 = { e2 ff [2] c6 f1 [2] ed dd [2] c3 ff [2] d7 e4 [2] d8 fe [2] c6 e3 [2] c4 e2 [2] df e4 [2] c3 e3 [2] df cc }

  condition:
    any of them
}