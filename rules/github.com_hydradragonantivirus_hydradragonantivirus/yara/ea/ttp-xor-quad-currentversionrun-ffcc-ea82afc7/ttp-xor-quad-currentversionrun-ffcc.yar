rule TTP_XOR_QUAD_CurrentVersionRun_ffcc {
  strings:
    $key_ffcc = { ac a3 [2] 88 ad [2] a3 81 [2] 8d a3 [2] 99 b8 [2] 96 a2 [2] 88 bf [2] 8a be [2] 91 b8 [2] 8d bf [2] 91 90 }

  condition:
    any of them
}