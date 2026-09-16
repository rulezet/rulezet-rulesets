rule TTP_XOR_WriteProcessMemory_dda2 {
  strings:
    $key_dda2 = { 8a d0 [2] b8 f2 [2] be c7 [2] 90 c7 [2] af db }

  condition:
    any of them
}