rule TTP_XOR_WriteProcessMemory_4229 {
  strings:
    $key_4229 = { 15 5b [2] 27 79 [2] 21 4c [2] 0f 4c [2] 30 50 }

  condition:
    any of them
}