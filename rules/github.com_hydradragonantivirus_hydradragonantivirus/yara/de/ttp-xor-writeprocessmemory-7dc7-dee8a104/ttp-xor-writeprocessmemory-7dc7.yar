rule TTP_XOR_WriteProcessMemory_7dc7 {
  strings:
    $key_7dc7 = { 2a b5 [2] 18 97 [2] 1e a2 [2] 30 a2 [2] 0f be }

  condition:
    any of them
}