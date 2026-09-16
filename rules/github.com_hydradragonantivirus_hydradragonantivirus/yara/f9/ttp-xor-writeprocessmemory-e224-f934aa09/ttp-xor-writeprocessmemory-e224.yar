rule TTP_XOR_WriteProcessMemory_e224 {
  strings:
    $key_e224 = { b5 56 [2] 87 74 [2] 81 41 [2] af 41 [2] 90 5d }

  condition:
    any of them
}