rule TTP_XOR_WriteProcessMemory_caf1 {
  strings:
    $key_caf1 = { 9d 83 [2] af a1 [2] a9 94 [2] 87 94 [2] b8 88 }

  condition:
    any of them
}