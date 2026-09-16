rule TTP_XOR_WriteProcessMemory_fda8 {
  strings:
    $key_fda8 = { aa da [2] 98 f8 [2] 9e cd [2] b0 cd [2] 8f d1 }

  condition:
    any of them
}