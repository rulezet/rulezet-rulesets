rule TTP_XOR_QUAD_CurrentVersionRun_f8cc {
  strings:
    $key_f8cc = { ab a3 [2] 8f ad [2] a4 81 [2] 8a a3 [2] 9e b8 [2] 91 a2 [2] 8f bf [2] 8d be [2] 96 b8 [2] 8a bf [2] 96 90 }

  condition:
    any of them
}