rule TTP_XOR_QUAD_CurrentVersionRun_62ff {
  strings:
    $key_62ff = { 31 90 [2] 15 9e [2] 3e b2 [2] 10 90 [2] 04 8b [2] 0b 91 [2] 15 8c [2] 17 8d [2] 0c 8b [2] 10 8c [2] 0c a3 }

  condition:
    any of them
}