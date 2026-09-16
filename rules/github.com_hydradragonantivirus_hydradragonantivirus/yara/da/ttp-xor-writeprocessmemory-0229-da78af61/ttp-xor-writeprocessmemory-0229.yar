rule TTP_XOR_WriteProcessMemory_0229 {
  strings:
    $key_0229 = { 55 5b [2] 67 79 [2] 61 4c [2] 4f 4c [2] 70 50 }

  condition:
    any of them
}