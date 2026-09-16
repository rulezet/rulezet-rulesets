rule TTP_XOR_WriteProcessMemory_2894 {
  strings:
    $key_2894 = { 7f e6 [2] 4d c4 [2] 4b f1 [2] 65 f1 [2] 5a ed }

  condition:
    any of them
}