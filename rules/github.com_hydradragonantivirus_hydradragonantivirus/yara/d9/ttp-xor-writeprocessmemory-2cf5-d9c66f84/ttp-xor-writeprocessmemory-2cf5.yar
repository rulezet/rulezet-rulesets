rule TTP_XOR_WriteProcessMemory_2cf5 {
  strings:
    $key_2cf5 = { 7b 87 [2] 49 a5 [2] 4f 90 [2] 61 90 [2] 5e 8c }

  condition:
    any of them
}