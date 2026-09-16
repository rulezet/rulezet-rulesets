rule TTP_XOR_WriteProcessMemory_0319 {
  strings:
    $key_0319 = { 54 6b [2] 66 49 [2] 60 7c [2] 4e 7c [2] 71 60 }

  condition:
    any of them
}