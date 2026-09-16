rule TTP_XOR_QUAD_CurrentVersionRun_7805 {
  strings:
    $key_7805 = { 2b 6a [2] 0f 64 [2] 24 48 [2] 0a 6a [2] 1e 71 [2] 11 6b [2] 0f 76 [2] 0d 77 [2] 16 71 [2] 0a 76 [2] 16 59 }

  condition:
    any of them
}