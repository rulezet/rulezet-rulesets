rule TTP_XOR_WriteProcessMemory_7631 {
  strings:
    $key_7631 = { 21 43 [2] 13 61 [2] 15 54 [2] 3b 54 [2] 04 48 }

  condition:
    any of them
}