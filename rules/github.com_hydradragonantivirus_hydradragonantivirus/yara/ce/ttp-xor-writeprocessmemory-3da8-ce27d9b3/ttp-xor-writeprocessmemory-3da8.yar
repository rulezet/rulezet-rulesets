rule TTP_XOR_WriteProcessMemory_3da8 {
  strings:
    $key_3da8 = { 6a da [2] 58 f8 [2] 5e cd [2] 70 cd [2] 4f d1 }

  condition:
    any of them
}