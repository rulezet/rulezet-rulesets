rule TTP_XOR_WriteProcessMemory_1ec4 {
  strings:
    $key_1ec4 = { 49 b6 [2] 7b 94 [2] 7d a1 [2] 53 a1 [2] 6c bd }

  condition:
    any of them
}