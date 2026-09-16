rule TTP_XOR_WriteProcessMemory_0cf5 {
  strings:
    $key_0cf5 = { 5b 87 [2] 69 a5 [2] 6f 90 [2] 41 90 [2] 7e 8c }

  condition:
    any of them
}