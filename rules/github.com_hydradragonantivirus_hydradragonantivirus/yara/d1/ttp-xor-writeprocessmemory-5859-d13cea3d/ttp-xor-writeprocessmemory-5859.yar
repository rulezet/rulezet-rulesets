rule TTP_XOR_WriteProcessMemory_5859 {
  strings:
    $key_5859 = { 0f 2b [2] 3d 09 [2] 3b 3c [2] 15 3c [2] 2a 20 }

  condition:
    any of them
}