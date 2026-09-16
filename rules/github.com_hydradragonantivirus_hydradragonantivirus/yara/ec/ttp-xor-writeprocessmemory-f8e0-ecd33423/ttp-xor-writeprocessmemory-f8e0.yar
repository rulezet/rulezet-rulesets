rule TTP_XOR_WriteProcessMemory_f8e0 {
  strings:
    $key_f8e0 = { af 92 [2] 9d b0 [2] 9b 85 [2] b5 85 [2] 8a 99 }

  condition:
    any of them
}