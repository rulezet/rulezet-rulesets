rule TTP_XOR_WriteProcessMemory_e959 {
  strings:
    $key_e959 = { be 2b [2] 8c 09 [2] 8a 3c [2] a4 3c [2] 9b 20 }

  condition:
    any of them
}