rule TTP_XOR_WriteProcessMemory_6c11 {
  strings:
    $key_6c11 = { 3b 63 [2] 09 41 [2] 0f 74 [2] 21 74 [2] 1e 68 }

  condition:
    any of them
}