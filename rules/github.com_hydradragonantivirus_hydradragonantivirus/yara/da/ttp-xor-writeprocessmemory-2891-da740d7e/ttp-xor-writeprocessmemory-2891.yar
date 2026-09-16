rule TTP_XOR_WriteProcessMemory_2891 {
  strings:
    $key_2891 = { 7f e3 [2] 4d c1 [2] 4b f4 [2] 65 f4 [2] 5a e8 }

  condition:
    any of them
}