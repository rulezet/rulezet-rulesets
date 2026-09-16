rule TTP_XOR_WriteProcessMemory_e214 {
  strings:
    $key_e214 = { b5 66 [2] 87 44 [2] 81 71 [2] af 71 [2] 90 6d }

  condition:
    any of them
}