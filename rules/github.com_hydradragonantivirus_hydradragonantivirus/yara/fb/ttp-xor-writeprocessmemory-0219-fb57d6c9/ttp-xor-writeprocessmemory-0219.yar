rule TTP_XOR_WriteProcessMemory_0219 {
  strings:
    $key_0219 = { 55 6b [2] 67 49 [2] 61 7c [2] 4f 7c [2] 70 60 }

  condition:
    any of them
}