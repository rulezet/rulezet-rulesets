rule TTP_XOR_QUAD_CurrentVersionRun_62f8 {
  strings:
    $key_62f8 = { 31 97 [2] 15 99 [2] 3e b5 [2] 10 97 [2] 04 8c [2] 0b 96 [2] 15 8b [2] 17 8a [2] 0c 8c [2] 10 8b [2] 0c a4 }

  condition:
    any of them
}