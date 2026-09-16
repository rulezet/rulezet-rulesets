rule TTP_XOR_QUAD_CurrentVersionRun_1493 {
  strings:
    $key_1493 = { 47 fc [2] 63 f2 [2] 48 de [2] 66 fc [2] 72 e7 [2] 7d fd [2] 63 e0 [2] 61 e1 [2] 7a e7 [2] 66 e0 [2] 7a cf }

  condition:
    any of them
}