rule TTP_XOR_WriteProcessMemory_0431 {
  strings:
    $key_0431 = { 53 43 [2] 61 61 [2] 67 54 [2] 49 54 [2] 76 48 }

  condition:
    any of them
}