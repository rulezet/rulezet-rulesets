rule TTP_XOR_WriteProcessMemory_4cd9 {
  strings:
    $key_4cd9 = { 1b ab [2] 29 89 [2] 2f bc [2] 01 bc [2] 3e a0 }

  condition:
    any of them
}