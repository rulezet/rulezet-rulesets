rule TTP_XOR_WriteProcessMemory_eaa8 {
  strings:
    $key_eaa8 = { bd da [2] 8f f8 [2] 89 cd [2] a7 cd [2] 98 d1 }

  condition:
    any of them
}