rule TTP_XOR_WriteProcessMemory_abb4 {
  strings:
    $key_abb4 = { fc c6 [2] ce e4 [2] c8 d1 [2] e6 d1 [2] d9 cd }

  condition:
    any of them
}