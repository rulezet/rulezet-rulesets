rule TTP_XOR_QUAD_CurrentVersionRun_bf88 {
  strings:
    $key_bf88 = { ec e7 [2] c8 e9 [2] e3 c5 [2] cd e7 [2] d9 fc [2] d6 e6 [2] c8 fb [2] ca fa [2] d1 fc [2] cd fb [2] d1 d4 }

  condition:
    any of them
}