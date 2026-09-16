rule TTP_XOR_WriteProcessMemory_cc37 {
  strings:
    $key_cc37 = { 9b 45 [2] a9 67 [2] af 52 [2] 81 52 [2] be 4e }

  condition:
    any of them
}