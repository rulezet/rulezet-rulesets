rule TTP_XOR_WriteProcessMemory_e039 {
  strings:
    $key_e039 = { b7 4b [2] 85 69 [2] 83 5c [2] ad 5c [2] 92 40 }

  condition:
    any of them
}