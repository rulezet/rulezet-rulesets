rule TTP_XOR_WriteProcessMemory_7de5 {
  strings:
    $key_7de5 = { 2a 97 [2] 18 b5 [2] 1e 80 [2] 30 80 [2] 0f 9c }

  condition:
    any of them
}