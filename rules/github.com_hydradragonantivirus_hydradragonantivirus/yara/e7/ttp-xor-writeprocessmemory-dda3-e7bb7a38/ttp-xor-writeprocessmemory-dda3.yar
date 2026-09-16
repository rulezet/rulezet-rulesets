rule TTP_XOR_WriteProcessMemory_dda3 {
  strings:
    $key_dda3 = { 8a d1 [2] b8 f3 [2] be c6 [2] 90 c6 [2] af da }

  condition:
    any of them
}