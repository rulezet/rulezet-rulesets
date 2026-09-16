rule TTP_XOR_WriteProcessMemory_fcd9 {
  strings:
    $key_fcd9 = { ab ab [2] 99 89 [2] 9f bc [2] b1 bc [2] 8e a0 }

  condition:
    any of them
}