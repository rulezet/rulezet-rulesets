rule TTP_XOR_WriteProcessMemory_cc67 {
  strings:
    $key_cc67 = { 9b 15 [2] a9 37 [2] af 02 [2] 81 02 [2] be 1e }

  condition:
    any of them
}