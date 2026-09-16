rule TTP_XOR_QUAD_CurrentVersionRun_a593 {
  strings:
    $key_a593 = { f6 fc [2] d2 f2 [2] f9 de [2] d7 fc [2] c3 e7 [2] cc fd [2] d2 e0 [2] d0 e1 [2] cb e7 [2] d7 e0 [2] cb cf }

  condition:
    any of them
}